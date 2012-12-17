# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2011 Zadara Storage Inc.
# Copyright (c) 2011 OpenStack LLC.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Generic code for PCI device management.

PCI devices are categorized into PCI device classes, identified by class name
(a string). Currently supported PCI device classes are:
    'net_vf' - a network device, which is a Virtual Function (VF),
               spawned by a SR-IOV-capable NIC
For non-supported PCI device classes, some default handling is provided.
"""

import json
import re

from nova import context
from nova import db
from nova import exception
from nova.openstack.common import cfg
from nova.openstack.common import lockutils
from nova.openstack.common import log as logging


"""
pci_devices helper:

The list of PCI devices available for allocation.
This is a list of JSON objects, that should be specified like this:
--pci_devices={"pci_addr": <PCI address, e.g., "0000:00:1e.0">,
               "pci_class": <PCI device class, e.g., "net_vf">,
               <class-specific-parameters>}
--pci_devices={"pci_addr": <PCI address, e.g., "0000:00:1e.1">,
               "pci_class": <PCI device class, e.g., "net_vf">,
               <class-specific-parameters>}
...

PCI device class may require additional class-specific parameters.
The "net_vf" class requires the following class-specific parameters:
    "network_id" - identifies the network, to which this VF is connected.
                   The network ID a simple string, which the administrator
                   uses to identify a network.
                   For example, it can be a name of a bridge created over
                   a NIC spawning the VFs.
    "parent_pf"  - identifies the parent physical NIC of this VF
"""

pci_device_opts = [
    cfg.MultiStrOpt('pci_devices',
                    default=[],
                    help='List of PCI devices available for allocation'),
    cfg.BoolOpt('pci_dynamic_discovery',
               default=False,
               help="Enable dynamic discovery of available PCI devices;"
                    "requires implementation in the subclass"),
    cfg.BoolOpt('pci_class_netvf_distribute_alloc_across_parentpf',
               default=False,
               help="Enable distribution of NET VFs from the same bucket "
                    "across parent PFs")
    ]

CONF = cfg.CONF
CONF.register_opts(pci_device_opts)

LOG = logging.getLogger(__name__)


class PciDevice(object):
    """
    Describes a PCI device: PCI address, PCI device class and class-specific
    parameters.

    PciDevice objects are compared by their identity (i.e., we don't define
    the __cmp__() method for this class.
    So in principle, it is possible to have two PciDevices having the same
    PciAddress.
    The user of the class ensures that he does not create more than one
    PciDevice with the same PCI address.
    """
    def __init__(self, pci_addr, pci_class, **kwargs):
        self.pci_addr = pci_addr.upper()
        self.pci_class = pci_class

        self._class_specific_params = kwargs.copy()

    def __getattr__(self, name):
        """
        Allows easy access to class-specific parameters
        """
        # Note that this method is called only when the attribute is not
        # found in "usual places"
        attr_val = self._class_specific_params.get(name)
        if not attr_val:
            raise AttributeError(name)

        return attr_val

    def __str__(self):
        pci_addr = self.pci_addr
        pci_class = self.pci_class
        class_specific = self._class_specific_params
        return _("[%(pci_addr)s|%(pci_class)s: %(class_specific)s]") % locals()


class PciDriver(object):
    """
    Provides top-level API for PCI device management.

    Most operations are generic and are not required to be overridden by
    derived classes.
    Several operations must be overridden.
    """

    def __init__(self):
        # Setup inventory managers
        self._global_inventory = PciGlobalInventory()
        self._inventory_managers = {
            # Add additional PCI device classes here when they are supported
            'net_vf': NetVfPciInventoryManager('net_vf', self)}

        # Setup the regular expression that matches a PCI device address
        hexa_char_re_str = r"[0-9a-fA-F]"
        octal_char_re_str = r"[0-7]"
        pci_addr_re_str = r"\A" + hexa_char_re_str + r"{4}" + r":" +\
                                  hexa_char_re_str + r"{2}" + r":" +\
                                  hexa_char_re_str + r"{2}" + r"." +\
                                  octal_char_re_str + r"\Z"
        self._pci_addr_re = re.compile(pci_addr_re_str)

        # Setup the regular expression that splits PCI addresses to
        # domain, bus, slot & function
        self._pci_addr_split_re = re.compile(r"[:.]")

        self._context = context.get_admin_context()

    def init_host(self, host, **kwargs):
        self.host = host

        self.init_host_subclass(**kwargs)

        if CONF.pci_devices:
            LOG.debug(_('Loading available PCI devices from flags'))
            # CONF.pci_devices is a python list of strings;
            # each string represents a JSON object(key/value pairs)
            for pci_dev_string in CONF.pci_devices:
                try:
                    # Raises ValueError/TypeError if there is a problem
                    pci_dev_dict = json.loads(pci_dev_string)
                except (TypeError, ValueError) as exc:
                    raise exception.InvalidInput(
                        reason=_("Failed parsing pci_devices flag: "\
                                 "%(pci_dev_string)s\n%(exc)s") % locals())

                self._add_pci_device_to_inventory(pci_dev_dict)

        if CONF.pci_dynamic_discovery:
            LOG.debug(_('Initiating PCI device dynamic discovery'))
            pci_device_dicts_lst = self.pci_device_discovery()
            for pci_dev_dict in pci_device_dicts_lst:
                self._add_pci_device_to_inventory(pci_dev_dict)

    @lockutils.synchronized('PciDriver.allocate_pci_devices', 'nova-')
    def allocate_pci_devices(self, instance):
        """
        This is the main function of the module, it performs PCI device
        allocation for the specified instance"

        According to the instance type, PCI device allocation requirements are
        determined. Then a DB query is performed to obtain all the
        currently-allocated PCI devices on this host. The results are compared
        against the in-memory inventory of all available PCI devices on this
        host. Free PCI devices are picked for the instance according to the
        instance type PCI allocation requirements. Finally, PCI allocation
        for the instance is committed in the db.

        Notes:
            - This function is fully re-entrant, i.e., it is possible to call
              this function several times. It will check whether all the
              required PCI allocated on this host, and will allocate
              the difference if needed
            - After calling this function, the caller will eventually call
              prepare_pci_devices_for_instance and get_allocated_pci_devices
        """

        instance_type = instance['instance_type']

        # Print
        instance_name = instance['name']
        it_name = instance_type['name']
        LOG.info(_("Attempting PCI device allocation for instance "\
            "%(instance_name)s, instance_type %(it_name)s") % locals())

        # Get PCI allocation requirements
        alloc_requirement_list = \
            self._pci_device_allocation_required(instance_type)
        if not alloc_requirement_list:
            # PCI allocation not required for this instance
            return

        # Go over all inventory managers and ask them to normalize the
        # allocation requirements
        for inventory_mgr in self._inventory_managers.itervalues():
            inventory_mgr.normalize_allocation_requirements(
                instance_name, alloc_requirement_list)

        # Fetch all the currently-allocated devices on this host, and also
        # the devices allocated to this instance
        all_alloc_devices_dict, instance_alloc_devices_dict = \
            self._find_allocated_pci_devices(instance['uuid'])

        # Update the PCI allocation requirements, according to what is already
        # allocated to this instance
        self._update_pci_device_allocation_requirements(
            alloc_requirement_list, instance_alloc_devices_dict)
        # If at this point we see that alloc_requirement_list becomes empty,
        # we are done
        if len(alloc_requirement_list) == 0:
            return

        # Allocate devices for the instance
        new_alloc_for_instance = \
            self._find_free_pci_devices_for_instance(instance_name,
                alloc_requirement_list,
                all_alloc_devices_dict)

        # We need at this point to update the DB
        # The current instance may have already-allocated devices
        # So we need to update its metadata entry in the DB
        for pci_class, pci_devices_set in new_alloc_for_instance.iteritems():
            if not instance_alloc_devices_dict.get(pci_class):
                # Note: we do not clone pci_devices_set here, because
                # we will not touch new_alloc_for_instance from now on
                instance_alloc_devices_dict[pci_class] = pci_devices_set
            else:
                instance_alloc_devices_dict[pci_class].update(pci_devices_set)

        # Now we have all the required information in
        # 'instance_alloc_devices_dict'
        # So we commit the allocation in the db
        LOG.info(_("Commit PCI devices for instance %s") % instance_name)
        for pci_class, pci_devices_set in \
            instance_alloc_devices_dict.iteritems():
            for pci_dev in pci_devices_set:
                LOG.info(_("    %(pci_dev)s") % locals())

        self._commit_instance_pci_devices_allocation(instance['uuid'],
            instance_alloc_devices_dict)

        # At this point it would be best to replace the appropriate
        # InstanceMetadata object in instance['metadata'] list.
        # But this is not easily possible, because of SqlAlchemy restrictions.
        # So we do a dirty trick: we cache instance_alloc_devices_dict in the
        # instance dictionary, and prepare_pci_devices_for_instance() and
        # get_allocated_pci_devices() will look there first
        instance['pci_devices'] = instance_alloc_devices_dict

        # Print
        LOG.info(_("PCI device allocation for instance %s completed")
                 % instance_name)

    def get_allocated_pci_devices(self, instance):
        """
        Returns a sequence of PCI device addresses currently-allocated for the
        instance, based on instance['metadata']

        This method only translates the information in instance metadata
        to a flat PCI addresses sequence. This method does not do any
        lookups in the db.

        Each element in the returned dictionary has the following entries:
            'pci_domain'
            'pci_bus'
            'pci_slot'
            'pci_function'
        """

        out_list = []

        # Try to get the cached entry first, then look at metadata
        instance_alloc_devices_dict = instance.get('pci_devices')
        if not instance_alloc_devices_dict:
            instance_alloc_devices_dict = \
                self._find_allocated_pci_devices_for_instance(instance)

        for pci_class_set in instance_alloc_devices_dict.itervalues():
            for pci_dev in pci_class_set:
                pci_domain, pci_bus, pci_slot, pci_function = \
                    self._pci_addr_split_re.split(pci_dev.pci_addr)
                # We need to append the 0x prefix, otherwise libvirt gets
                # confused with strings like "0010" and "0A", because it thinks
                # these are in octal base
                out_list.append(dict(pci_domain='0x' + pci_domain,
                                     pci_bus='0x' + pci_bus,
                                     pci_slot='0x' + pci_slot,
                                     pci_function='0x' + pci_function))

        return out_list

    def prepare_pci_devices_for_instance(self, instance):
        """
        Must be called right before an instance is run
        """

        # Try to get the cached entry first, then look at metadata
        instance_alloc_devices_dict = instance.get('pci_devices')
        if not instance_alloc_devices_dict:
            instance_alloc_devices_dict = \
                self._find_allocated_pci_devices_for_instance(instance)

        for pci_class_set in instance_alloc_devices_dict.itervalues():
            for pci_dev in pci_class_set:
                self.pci_device_prepare_for_use(pci_dev)

    def has_network_pci_devices(self, instance, network, mapping, plugging):
        """
        Checks whether the specified instance has PCI device(s), which can
        serve as network interfaces for the specified (network,mapping) pair.
        Returns True if yes, False otherwise.
        Parameters:
            instance - as returned by "instance_get"; must be after PCI device
                       allocation
            network, mapping - same as passed to VIFDriver.plug() method
            plugging - whether we want to plug or unplug the network interface
        """
        result = False

        # Try to get the cached entry first, then look at metadata
        instance_alloc_devices_dict = instance.get('pci_devices')
        if not instance_alloc_devices_dict:
            instance_alloc_devices_dict = \
                self._find_allocated_pci_devices_for_instance(instance)

        for pci_class, pci_class_set in \
            instance_alloc_devices_dict.iteritems():
            # Currently, there is only one class that can perhaps satisfy
            if pci_class == 'net_vf':
                inventory_mgr = self._inventory_managers['net_vf']
                result = result or inventory_mgr.has_network_pci_devices(
                                        pci_class_set,
                                        network,
                                        mapping,
                                        plugging)

        return result

    #############################################################
    # The following methods must be overridden by derived classes
    def init_host_subclass(self, **kwargs):
        """
        Called within the context of init_host(), before starting to
        initialize the inventory
        """
        raise NotImplementedError()

    def pci_device_discovery(self):
        """
        Returns a list of PCI devices discovered dynamically.

        The return value must be a list of dictionaries; each dictionary
        must be in the form acceptable by '_add_pci_device_to_inventory'
        """
        raise NotImplementedError()

    def pci_device_init_subclass(self, pci_dev):
        """
        This method is called on startup, right after a new PciDevice object
        has been created.
        This method is supposed to do whatever subclass-specific
        initialization necessary.
        """
        raise NotImplementedError()

    def pci_device_prepare_for_use(self, pci_dev):
        """
        Prepare a PCI device for usage by an instance.

        This may include unbinding the device from its current driver,
        resetting the device etc.
        pci_dev is a PciDevice object
        """
        raise NotImplementedError()

    def pci_device_set_mac(self, pci_dev, mac, index):
        """
        This method is relevant only for network PCI devices, such SR-IOV
        Virtual Functions
        """
        raise NotImplementedError()

    #############################################################
    # Private methods
    def _add_pci_device_to_inventory(self, pci_dev_dict):
        """
        Add a single PCI device to the inventory during PciDriver startup

        pci_dev_dict is a dictionary with the following entries:
            'pci_addr' : PCI device address in the form of '0000:00:1e.0'
            'pci_class': PCI device class, must be one of the supported
                         classes, e.g., 'net_vf'
            rest of the entries are class-specific
        """
        # Extract and verify the PCI device address
        pci_addr = pci_dev_dict.get('pci_addr')
        if not pci_addr:
            raise exception.InvalidInput(
            reason=_("Missing 'pci_addr' key in %s") % pci_dev_dict)
        if not self._pci_addr_re.match(pci_addr):
            raise exception.InvalidInput(
            reason=_("PCI address %s is seems to be illegal") % pci_addr)

        # We don't need the pci address in the dictionary anymore
        del pci_dev_dict['pci_addr']

        # Make sure that PCI address is in uppercase!
        pci_addr = pci_addr.upper()

        # Extract and verify the PCI device class
        pci_class = pci_dev_dict.get('pci_class')
        if not pci_class:
            raise exception.InvalidInput(
                reason=_("Missing 'pci_class' key in %s)") % pci_dev_dict)

        # We don't need the pci class in the dictionary anymore
        del pci_dev_dict['pci_class']

        # Create a PciDevice object
        pci_dev = PciDevice(pci_addr, pci_class, **pci_dev_dict)
        self.pci_device_init_subclass(pci_dev)

        # Add the PCI device to the global inventory and to apropriate
        # inventory manager
        self._global_inventory.add_pci_device(pci_dev)

        inventory_mgr = self._inventory_managers.get(pci_class)
        if not inventory_mgr:
            inventory_mgr = DefaultPciInventoryManager(pci_class, self)
            self._inventory_managers[pci_class] = inventory_mgr

        inventory_mgr.add_pci_device(pci_dev)

    def _pci_device_allocation_required(self, instance_type):
        """
        Returns a list of dictionaries with PCI allocation requirements.
        If no PCI allocation is required, returns None

        Each dictionary in the list is in the following format:
            'pci_class' : the name of the PCI class
            'count'     : the number of devices to allocate from that class
            ....        : additional class-specific parameters
        """

        # Note: at this point instance_type comes from joinedload with
        # instance, so extra_specs are not loaded
        extra_specs = db.instance_type_extra_specs_get(self._context,
                                                       instance_type['flavorid'])
        if not extra_specs:
            return None

        pci_devices_str = extra_specs.get('pci_devices')
        if not pci_devices_str:
            return None

        # Convert the JSON string into a list of python dictionaries
        # Then verify the list of dictionaries, since we're going to return it
        try:
             # Raises ValueError/TypeError if there is a problem
            dict_list = json.loads(pci_devices_str)
            if not isinstance(dict_list, list):
                raise ValueError(_("Top-level object is not a JSON array"))

            # Verify each dictionary in the list
            for pci_class_dict in dict_list:
                if not isinstance(pci_class_dict, dict):
                    raise ValueError(_("Array entry %s is not a JSON object"\
                        " (key/value dict)") % str(pci_class_dict))

                pci_class = pci_class_dict.get('pci_class')
                devs_count = pci_class_dict.get('count')
                if not pci_class or not devs_count:
                    raise ValueError(_("No 'pci_class' or 'count' in %s") %
                        str(pci_class_dict))

                int(devs_count)  # Raises TypeError if not an integer
                if devs_count <= 0:
                    raise ValueError(_("'count' should be positive!"))

                it_name = instance_type['name']
                LOG.info(_("Instance type %(it_name)s requires "\
                    "%(devs_count)s %(pci_class)s devices: "\
                    "%(pci_class_dict)s") % locals())

            # Looks ok, return the allocation requirements dictionary
            return dict_list

        except (ValueError, TypeError) as exc:
            # If there is a wrong entry in the DB, log an error and
            # return an empty allocation
            it_name = instance_type['name']
            LOG.error(_("Instance type %(it_name)s has an illegal "\
                "pci_devices string in extra_specs: %(pci_devices_str)s\n"\
                "Error: %(exc)s") % locals())
            return None

    def _find_allocated_pci_devices(self, instance_id):
        """
        Returns all the PCI devices currently allocated on this host.

        This is achieved by looking up all instances running on the current
        host in the db.
        This method is a wrapper over _find_allocated_pci_devices_for_instance

        Returns a 2-tuple of dictionaries.
        First dictionary describes all the PCI devices allocated on this host.
        It has the following key/value pairs:
            key:   PCI class name
            value: a set of PciDevice objects
        Second dictionary describes the allocation only for the
            specified instance (in the same format)
        """

        out_all_dict = {}
        out_instance_dict = {}

        instances = db.instance_get_all_by_host(self._context, self.host)
        for instance in instances:
            instance_dict = \
                self._find_allocated_pci_devices_for_instance(instance)

            self._print_allocated_pci_devices_for_instance(instance,
                                                           instance_dict)

            # Set the output for the instance
            if instance_id == instance['uuid']:
                out_instance_dict = instance_dict

            # Update the global output with this instance's data
            for pci_class, pci_devices_set in instance_dict.iteritems():
                out_set_for_pci_class = out_all_dict.get(pci_class)
                if not out_set_for_pci_class:
                    # NOTE!!
                    # It is important to clone the pci_devices_set here,
                    # othewise out_instance_dict and out_all_dict[pci_class]
                    # will point to the same set, and later we will add
                    # devices to this set, so out_instance_dict will get
                    # messed up
                    out_all_dict[pci_class] = set(pci_devices_set)
                else:
                    out_set_for_pci_class.update(pci_devices_set)

        return out_all_dict, out_instance_dict  # Return a 2-tuple

    def _find_allocated_pci_devices_for_instance(self, instance):
        """
        Returns all the PCI devices allocated by the specified instance
        on this host.

        This method doesn't do any db query, it only looks at
        instance['metadata']
        Returns a dictionary that has the following key/value pairs:
            key:   PCI class name
            value: a set of PciDevice objects
        """

        # Fetch the 'pci_devices_<hostname>' metadata key
        metadata = instance.get('metadata')
        if not metadata:
            return {}

        # Metadata is a list of InstanceMetadata objects....
        # Let's find the correct one...and hope there is only one
        pci_devices_str = None
        metadata_key = 'pci_devices_' + self.host
        for metadata_obj in metadata:
            if metadata_obj.get('key') == metadata_key:
                pci_devices_str = metadata_obj.get('value')
                break
        if not pci_devices_str:
            return {}

        # Convert the pci_devices key to a python list PCI addresses
        try:
            # This may throw a ValueError in case of malformed JSON
            pci_addr_list = json.loads(pci_devices_str)
            if not isinstance(pci_addr_list, list):
                raise ValueError(_("Top-level object is not a JSON array"))
        except (TypeError, ValueError) as exc:
            instance_name = instance['name']
            LOG.error(_("Instance %(instance_name)s has a malformed "\
                "pci_devices string in metadata:\n"\
                "%(pci_devices_str)s\nError: %(exc)s") %locals())
            return {}

        # Go over entries in pci_addr_list, check them, produce output
        out_dict = {}  # The output dictionary
        for pci_addr in pci_addr_list:
            pci_dev = self._global_inventory.get_pci_device(pci_addr.upper())
            if not pci_dev:
                instance_name = instance['name']
                LOG.error(_("Instance %(instance_name)s: no PciDevice found "\
                            "for PCI address: %(pci_addr)s") % locals())
                continue  # Move to next PCI address

            # Add pci_dev to output (if not already there)
            out_pci_class_set = out_dict.get(pci_dev.pci_class)
            if not out_pci_class_set:
                out_pci_class_set = set()
                out_dict[pci_dev.pci_class] = out_pci_class_set

            out_pci_class_set.add(pci_dev)

        return out_dict

    def _print_allocated_pci_devices_for_instance(self, instance, alloc_dict):
        """
        Prints out the dictionary returned by
        _find_allocated_pci_devices_for_instance
        """

        if not alloc_dict:
            LOG.info(_("Already-allocated PCI devices for instance %s: NONE") %
                     instance['name'])
        else:
            LOG.info(_("Already-allocated PCI devices for instance %s:") %
                     instance['name'])
            for pci_class_set in alloc_dict.itervalues():
                for pci_dev in pci_class_set:
                    LOG.info(_("    %(pci_dev)s") % locals())

    def _update_pci_device_allocation_requirements(self,
            alloc_requirement_list, instance_alloc_devices_dict):
        """
        This method accounts for already-allocated PCI devices for the
        instance.

        It looks in 'instance_alloc_devices_dict' and updates the
        'alloc_requirement_list' accordingly.
        If some entry in 'alloc_requirement_list' ends up with 'count'==0,
        this entry is removed totally from 'alloc_requirement_list'.
        This method delegates to inventory managers to do the job.

        Parameters:
        - alloc_requirement_list - as returned by
                                   _pci_device_allocation_required
        - instance_alloc_devices_dict - as returned by
                                   _find_allocated_pci_devices_for_instance
        """
        for pci_class, inventory_mgr in self._inventory_managers.iteritems():
            alloc_for_pci_class_set = \
                instance_alloc_devices_dict.get(pci_class)
            if not alloc_for_pci_class_set:
                # We don't have anything already-allocated for that class
                # So nothing to do
                continue
            inventory_mgr.update_allocation_requirements(
                alloc_requirement_list, alloc_for_pci_class_set)

    def _find_free_pci_devices_for_instance(self, instance_name,
                                            alloc_requirement_list,
                                            all_alloc_devices_dict):
        """
        Finds PCI devices suitable to be allocated for the instance, according
        to PCI allocation requirements and currently-allocated devices.

        This method invokes appropriate inventory managers to do the
        allocation job.
        Parameters:
            alloc_requirement_list - as returned by
                                     _pci_device_allocation_required
            all_alloc_devices_dict - as returned by
                                     _find_allocated_pci_devices

        Returns a dictionary that has the following key/value pairs:
            key:   PCI class name
            value: a set of PciDevice objects

        Note: there is no internal persistency of the allocations, meaning that
              after returning, there is no "memory" that particular PCI
              devices were allocated. So a second call to this method with
              same arguments might return exactly the same PCI devices.
        Note: upon return of this function, the 'all_alloc_devices_dict' will
            be updated to contain also the newly-allocated devices
        """

        out_dict = {}

        for alloc_requirement_dict in alloc_requirement_list:
            # Obtain the pci_class and an inventory manager for this class
            pci_class = alloc_requirement_dict['pci_class']
            inventory_mgr = self._inventory_managers.get(pci_class)
            if not inventory_mgr:
                # If we don't have the default inventory manager, this means
                # we don't have any available PCI devices of that class
                LOG.error(_("No inventory manager for PCI class %(pci_class)s"\
                            " for instance %(instance_name)s") % locals())
                raise exception.PciDeviceAllocationFailed(name=instance_name)

            # Fetch the set of currently-allocated devices for 'pci_class'
            alloc_for_pci_class_set = all_alloc_devices_dict.get(pci_class)
            if not alloc_for_pci_class_set:
                alloc_for_pci_class_set = set()
                all_alloc_devices_dict[pci_class] = alloc_for_pci_class_set

            # Ask the inventory manager to perform the allocation
            alloc_for_instance_set = inventory_mgr.find_free_pci_devices(
                alloc_requirement_dict,
                alloc_for_pci_class_set)
            if not alloc_for_instance_set:
                raise exception.PciDeviceAllocationFailed(name=instance_name)

            # Update the all_alloc_devices_dict
            # (by updating alloc_for_pci_class_set)
            # This is required if there are several entries for the same
            # PCI class in alloc_requirement_list
            alloc_for_pci_class_set.update(alloc_for_instance_set)

            # Set/Append to the output
            out_set_for_pci_class = out_dict.get(pci_class)
            if not out_set_for_pci_class:
                # Note: it's ok not to clone alloc_for_instance_set here
                out_dict[pci_class] = alloc_for_instance_set
            else:
                out_set_for_pci_class.update(alloc_for_instance_set)

        LOG.info(_("Newly-allocated PCI devices for instance %s:") %
                   instance_name)
        for pci_class_set in out_dict.itervalues():
            for pci_dev in pci_class_set:
                LOG.info(_("    %(pci_dev)s") % locals())

        return out_dict

    def _commit_instance_pci_devices_allocation(self, instance_id,
                                                instance_alloc_devices_dict):
        """
        Commits the PCI device allocation for the specified instance,
        by creating/replacing its 'pci_devices' entry in the
        'instance_metadata' table.

        instance_alloc_devices_dict - a dictionary that contains entries like:
            key: PCI device class name
            value: a set of PciDevice objects
        """

        # Build the python representation of the 'pci_devices_<hostname>'
        # entry in the 'instance_metadata' table
        pci_addr_list = []
        for pci_devices_set in instance_alloc_devices_dict.itervalues():
            pci_addr_for_pci_class_list = \
                [pci_dev.pci_addr for pci_dev in pci_devices_set]
            pci_addr_list.extend(pci_addr_for_pci_class_list)

        # Now produce a JSON string representation of all this
        pci_devices_str = json.dumps(pci_addr_list)

        # Finally, write to db
        metadata_upd_dict = {'pci_devices_' + self.host: pci_devices_str}
        db.instance_metadata_update(self._context, instance_id,
                                    metadata_upd_dict,
                                    # The last argument is 'delete',
                                    # which we set to False!
                                    False)


##############################################################################
class PciGlobalInventory(object):
    def __init__(self):
        self._devices = dict()

    def add_pci_device(self, pci_dev):
        """
        Adds the specified PCI device to the global inventory.
        Currently this is used only for global duplicate PCI address check.
        """

        if self._devices.get(pci_dev.pci_addr):
            raise exception.DuplicatePciDeviceAddress(
                pci_address=pci_dev.pci_addr)

        self._devices[pci_dev.pci_addr] = pci_dev

    def get_pci_device(self, pci_addr):
        """
        Returns the PciDevice object according to the specified PCI address or
        None if no such PciDevice exists
        """
        return self._devices.get(pci_addr)


##############################################################################
class PciInventoryManager(object):
    """
    Superclass of all class-specific inventory managers"
    """

    def __init__(self, pci_class, pci_driver):
        self.pci_class = pci_class
        self.pci_driver = pci_driver

    #############################################################
    # The following methods must be overridden by derived classes
    def add_pci_device(self, pci_dev):
        """
        Adds the specified PCI device to the inventory.

        The method must be overridden by subclasses.
        This method is called during startup
        pci_dev - a PciDevice object
        """
        raise NotImplementedError()

    def normalize_allocation_requirements(self, instance_name,
        alloc_requirement_list):
        """
        This gives a chance to the inventory manager to modify the allocation
        requirements list in a way, that will allow more convenient handling
        of allocation requests.

        This method is called right after the allocation requirement list for
        a particular instance type is fetched from the databasse, and before
        any other calls are attempted for the inventory manager on behalf
        of this instance.
        The implementation is allowed to modify the passed
        alloc_requirement_list.

        Parameters:
         - instance_name: only for printing/raisng
         - alloc_requirement_list: exactly as returned by
           _pci_device_allocation_required
        """
        raise NotImplementedError()

    def update_allocation_requirements(self, alloc_requirement_list,
                                             alloc_for_pci_class_set):
        """
        This method accounts for already-allocated PCI devices for the
        instance.

        It looks in 'alloc_for_pci_class_set' and updates the
        'alloc_requirement_list' accordingly.
        If some entry in 'alloc_requirement_list' ends up with 'count'==0,
        this entry is removed totally from 'alloc_requirement_list'.

        Parameters:
        - alloc_requirement_list:
            as returned by _pci_device_allocation_required, after normalization
            by normalize_allocation_requirements
        - alloc_for_pci_class_set - a set of PciDevice objects, already
            allocated for this class
        """
        raise NotImplementedError()

    def find_free_pci_devices(self, alloc_requirement_dict,
                              alloc_for_pci_class_set):
        """
        Finds free PCI devices according to the allocation requiremtns,
        allocated devices and in-memory inventory.

        alloc_requirement_dict - a dictionary with the following entries:
            'count' - how many PCI devices of this class to allocate
            ...     - other, PCI-class specific parameters
        alloc_for_pci_class_set - a set of PciDevice objects,
                                  already-allocated for this class
        Returns:
            a set of allocated PciDevice objects, or None if allocation failed

        """
        raise NotImplementedError()


##############################################################################
class DefaultPciInventoryManager(PciInventoryManager):
    """
    Provides default, very rudimentary inventory management"

    An instance of DefaultPciInventoryManager is created for each
    PCI device class, for which there is no dedicated inventory manager.
    So an instnce of DefaultPciInventoryManager is handling PCI devices
    of one PCI class.
    """

    def __init__(self, pci_class, pci_driver):
        super(DefaultPciInventoryManager, self).__init__(pci_class, pci_driver)
        self._my_devices = set()

    def add_pci_device(self, pci_dev):
        pci_class = self.pci_class
        LOG.info(_("DefaultPciInventoryManager %(pci_class)s: adding "\
                    "PCI device %(pci_dev)s") % locals())
        # No need for duplicate check here;
        # this is done by the global inventory
        self._my_devices.add(pci_dev)

    def normalize_allocation_requirements(self, instance_name,
        alloc_requirement_list):
        # If there are multiple entries with our pci_class,
        # let's make them one entry
        # Since we are in default inventory manager, we know nothing of
        # class-specific parameters, so we ignore and eventually drop them
        total_count = 0

        # We are going to modify alloc_requirement_list, so let's iterate over
        # a copy, while we modify the original
        copy_tuple = tuple(alloc_requirement_list)
        for alloc_requirement_dict in copy_tuple:
            if alloc_requirement_dict['pci_class'] == self.pci_class:
                total_count = total_count + alloc_requirement_dict['count']
                alloc_requirement_list.remove(alloc_requirement_dict)

        # Create an accumulative single entry, if needed
        if total_count > 0:
            pci_class = self.pci_class
            LOG.info(_("DefaultPciInventoryManager %(pci_class)s: "\
                       "normalized count: %(total_count)s") % locals())
            alloc_requirement_list.append(dict(pci_class=self.pci_class,
                                               count=total_count))

    def update_allocation_requirements(self, alloc_requirement_list,
                                             alloc_for_pci_class_set):
        # If nothing is allocated for us, nothing to do
        if len(alloc_for_pci_class_set) == 0:
            return

        # Let's find our only requirement entry (we know there is only one,
        # because it's after normalization
        my_alloc_requirement_dict = None
        for alloc_requirement_dict in alloc_requirement_list:
            if alloc_requirement_dict['pci_class'] == self.pci_class:
                my_alloc_requirement_dict = alloc_requirement_dict
                break
        if not my_alloc_requirement_dict:
            # Nothing to do
            return

        need_count = my_alloc_requirement_dict['count']
        already_count = len(alloc_for_pci_class_set)
        pci_class = self.pci_class  # This is just for printing
        if need_count <= already_count:
            LOG.info(_("DefaultPciInventoryManager %(pci_class)s: needed "\
                "%(need_count)s, already-allocated %(already_count)s => "\
                "nothing to do") % locals())
            alloc_requirement_list.remove(my_alloc_requirement_dict)
        else:
            LOG.info(_("DefaultPciInventoryManager %(pci_class)s: needed "\
                "%(need_count)s, already-allocated %(already_count)s") %
                locals())
            my_alloc_requirement_dict['count'] = need_count - already_count

    def find_free_pci_devices(self, alloc_requirement_dict,
                              alloc_for_pci_class_set):
        count = alloc_requirement_dict['count']
        # Just a safety check; somewhere else is verified that count > 0
        if not count:
            return None

        # Just a printout
        self_id = id(self)
        LOG.info(_("DefaultPciInventoryManager %(self_id)s: "\
                   "Free PCI devices:") % locals())
        for pci_dev in self._my_devices:
            LOG.info(_("    %(pci_dev)s") % locals())

        out_set = set()
        for pci_dev in self._my_devices:
            if pci_dev not in alloc_for_pci_class_set:
                out_set.add(pci_dev)
                count = count - 1
                if count == 0:
                    break

        if count > 0:
            return None

        return out_set


##############################################################################
class NetVfPciInventoryManager(PciInventoryManager):
    """
    Implementation of PciInventoryManager for the 'net_vf' PCI device class
    """

    class NetVfNetworkBucket(object):
        """
        Represents an inventory of all 'net_vf' PCI devices that have
        the same network_id
        """

        def __init__(self, network_id):
            self.network_id = network_id
            # key: parent PF, value: set of PciDevice objects
            self._pf_sets_dict = dict()
            self._allocated = set()
            pass

        def add_pci_device(self, pci_dev, do_print=True):
            """
            Called during startup, to initialize the inventory
            """

            pf_set = self._pf_sets_dict.get(pci_dev.parent_pf)
            if not pf_set:
                pf_set = set()
                self._pf_sets_dict[pci_dev.parent_pf] = pf_set

            # Note that PciDevice objects are compared by identity!
            pf_set.add(pci_dev)

            if do_print:
                self_id = id(self)
                self_net_id = self.network_id
                LOG.info(_("NetVfNetworkBucket %(self_id)s, "\
                    "network_id %(self_net_id)s: added PCI device "\
                    "%(pci_dev)s") % locals())

        def mark_pci_device_allocated(self, pci_dev):
            """
            Called during allocation for the devices that are already allocated
            """

            # If we don't find this PCI device in our bucket, it's a warning
            pf_set = self._pf_sets_dict.get(pci_dev.parent_pf)
            if not pf_set:
                self_id = id(self)
                self_net_id = self.network_id
                parent_pf = pci_dev.parent_pf
                LOG.warn(_("NetVfNetworkBucket %(self_id)s, "\
                    "network_id %(self_net_id)s: parent_pf %(parent_pf)s "\
                    "is not in the bucket!") %
                    locals())
                return

            if pci_dev not in pf_set:
                self_id = id(self)
                self_net_id = self.network_id
                parent_pf = pci_dev.parent_pf
                LOG.warn(_("NetVfNetworkBucket %(self_id)s, "\
                    "network_id %(self_net_id)s: PCI device: %(pci_dev)s, "\
                    "parent_pf %(parent_pf)s is not in the bucket!")
                    % locals())
                return

            # Put this PCI device aside
            pf_set.remove(pci_dev)
            self._allocated.add(pci_dev)

        def allocate_pci_devices(self, count):
            """
            Asks to allocate 'count' devices from this bucket

            Returns a set of PciDevice objects if successful,
            otherwise returns None
            """

            num_allocated = 0
            out_set = set()
            self_id = id(self)
            self_net_id = self.network_id
            num_pf_sets = len(self._pf_sets_dict)

            # Lets first check if we can satisfy this allocation

            # if we need to mandate distributing allocations across
            # parent-pfs & we cannot, return
            if CONF.pci_class_netvf_distribute_alloc_across_parentpf and \
                (count % num_pf_sets) != 0:
                LOG.error(_("NetVfNetworkBucket %(self_id)s, network_id "\
                    "%(self_net_id)s: Cannot mandate distributing %(count)d "\
                    "allocs across %(num_pf_sets)d PF sets") % locals())
                return None

            num_allocs_per_pf_set = count / num_pf_sets

            # count available to see if we can satisfy this allocation
            num_available = 0
            for parent_pf, pf_set in self._pf_sets_dict.iteritems():
                num_available += len(pf_set)

                # If we need to mandate, each parent-pf must accomodate 
                # num_allocs_per_pf_set
                if CONF.pci_class_netvf_distribute_alloc_across_parentpf and \
                    len(pf_set) < num_allocs_per_pf_set:
                    LOG.error(_("NetVfNetworkBucket %(self_id)s, network_id "\
                        "%(self_net_id)s: Not enough free VF in %(parent_pf)s"\
                        " PF set. rqd:%(num_allocs_per_pf_set)d") % locals())
                    return None

            if num_available < count:
                LOG.error(_("NetVfNetworkBucket %(self_id)s, network_id "\
                    "%(self_net_id)s: Not enough free VFs in all PFsets. "\
                    "rqd:%(count)d avl:%(num_available)d") % locals())
                return None

            # do the allocations
            for pf_set in self._pf_sets_dict.itervalues():
                # if we are not mandated to distribute,
                # go ahead & grab maximum from a pf-set
                if not CONF.pci_class_netvf_distribute_alloc_across_parentpf:
                    num_allocs_per_pf_set = min(len(pf_set), \
                                            count - num_allocated)

                for val in xrange(num_allocs_per_pf_set):
                    pci_dev = pf_set.pop()
                    self._allocated.add(pci_dev)
                    num_allocated = num_allocated + 1
                    out_set.add(pci_dev)

                if num_allocated == count:
                    break

            return out_set

        def clear_allocated(self):
            """
            This must be called at the end of allocation process
            """

            for pci_dev in self._allocated:
                self.add_pci_device(pci_dev, do_print=False)
            self._allocated.clear()

        def print_free_pci_devices(self):
            self_id = id(self)
            self_net_id = self.network_id
            LOG.info(_("NetVfNetworkBucket %(self_id)s, network_id "\
                       "%(self_net_id)s free PCI devices:") % locals())
            for parent_pf, pf_set in self._pf_sets_dict.iteritems():
                for pci_dev in pf_set:
                    LOG.info(_("    %(pci_dev)s") % locals())

    def __init__(self, pci_class, pci_driver):
        if pci_class != 'net_vf':
            raise exception.InvalidInput(reason=_("pci_class should be "\
                "'net_vf', not %(pci_class)s") % locals())

        super(NetVfPciInventoryManager, self).__init__(pci_class, pci_driver)
        # key: network_id, value: NetVfNetworkBucket
        self._network_buckets = dict()

    def add_pci_device(self, pci_dev):
        """
        Additional arguments required for 'net_vf' class:
            'network_id' : identifies the network,
                           to which this VF is connected
            'parent_pf'  : identifies the parent physical NIC of this VF
        """

        # Check that additional arguments are present
        if not hasattr(pci_dev, "network_id") or \
           not hasattr(pci_dev, "parent_pf"):
            raise exception.InvalidInput(reason=_("Not all net_vf-specific "\
                "parameters specified for %(pci_dev)s") % locals())

        # Add to the network bucket
        # Note: we allow here to add 2 PCI devices of different networks,
        # but having the same parent PF
        # Not sure if that is possible, but let's not block it for now

        network_bucket = self._network_buckets.get(pci_dev.network_id)
        if not network_bucket:
            network_bucket = \
                NetVfPciInventoryManager.NetVfNetworkBucket(pci_dev.network_id)
            self._network_buckets[pci_dev.network_id] = network_bucket
        network_bucket.add_pci_device(pci_dev)

    def normalize_allocation_requirements(self, instance_name,
        alloc_requirement_list):
        # We will get rid of entries with network_id==None and expand them
        # into specific network_id
        # We also make sure we have a single entry for each network_id
        normalized_alloc_requirement_dict = dict()

        def _add_to_normalized(network_id, count):
            prev_count = normalized_alloc_requirement_dict.get(network_id)
            if prev_count is None:
                normalized_alloc_requirement_dict[network_id] = count
            else:
                normalized_alloc_requirement_dict[network_id] = prev_count +\
                                                                count

        # We are going to modify alloc_requirement_list, so let's iterate over
        # a copy, while we modify the original
        copy_tuple = tuple(alloc_requirement_list)
        for alloc_requirement_dict in copy_tuple:
            if alloc_requirement_dict['pci_class'] != 'net_vf':
                continue

            count = alloc_requirement_dict['count']
            network_id = alloc_requirement_dict.get('network_id')
            if network_id is None:
                # It is required to allocate from all available networks.
                # But if the inventory is totally empty, we need to raise here,
                # otherwise, we may leave an empty alloc_requirement_list,
                # and the caller may further think that allocation succeeded
                if len(self._network_buckets) == 0:
                    LOG.error(_('NetVf inventory is empty!'))
                    raise exception.PciDeviceAllocationFailed(
                        name=instance_name)

                # We need 'count' devices from all networks we have
                for network_id in self._network_buckets.iterkeys():
                    _add_to_normalized(network_id, count)
            else:
                # If there are no PCI devices from that network_id,
                # allocation will fail later; we only normalize here
                _add_to_normalized(network_id, count)
            alloc_requirement_list.remove(alloc_requirement_dict)

        if len(normalized_alloc_requirement_dict) > 0:
            LOG.info(_("NetVfPciInventoryManager: Normalized PCI allocation "\
                        "requirements:"))
            for network_id, count in \
                normalized_alloc_requirement_dict.iteritems():
                LOG.info(_("  network_id: %(network_id)s, count: %(count)s") %
                         locals())
                alloc_requirement_list.append(dict(pci_class='net_vf',
                                                   count=count,
                                                   network_id=network_id))

    def update_allocation_requirements(self, alloc_requirement_list,
                                             alloc_for_pci_class_set):
        # If nothing is allocated for us, nothing to do
        if len(alloc_for_pci_class_set) == 0:
            return

        # Let's count the number of devices allocated per network_id
        count_per_network = dict()
        for pci_dev in alloc_for_pci_class_set:
            count = count_per_network.get(pci_dev.network_id)
            if count is None:
                count_per_network[pci_dev.network_id] = 1
            else:
                count_per_network[pci_dev.network_id] = count + 1

        LOG.info(_("NetVfPciInventoryManager: updating allocation "\
                    "requirements"))

        requirement_dicts_to_drop = []

        for alloc_requirement_dict in alloc_requirement_list:
            if alloc_requirement_dict['pci_class'] != 'net_vf':
                continue

            # We know that there is a single entry per each network_id,
            # because we have normalized the allocation requirements list
            network_id = alloc_requirement_dict['network_id']
            need_count = alloc_requirement_dict['count']
            already_count = count_per_network.get(network_id)
            if already_count is None:
                # We don't have any existing allocation
                LOG.info(_("  network_id %(network_id)s: nothing "\
                           "already-allocated") % locals())
                continue
            if need_count <= already_count:
                # We don't have to allocate
                LOG.info(_("  network_id %(network_id)s: needed "\
                    "%(need_count)s, already-allocated %(already_count)s "\
                    "=> nothing to do") % locals())
                requirement_dicts_to_drop.append(alloc_requirement_dict)
            else:
                # We have to allocate the difference
                LOG.info(_("  network_id %(network_id)s: needed "\
                    "%(need_count)s, already-allocated %(already_count)s")
                    % locals())
                alloc_requirement_dict['count'] = need_count - already_count

        # Drop those that don't need anymore allocations
        for alloc_requirement_dict in requirement_dicts_to_drop:
            alloc_requirement_list.remove(alloc_requirement_dict)

    def find_free_pci_devices(self, alloc_requirement_dict,
                                    alloc_for_pci_class_set):
        network_id = alloc_requirement_dict.get('network_id')
        count = alloc_requirement_dict['count']

        # The idea here is the same as in DefaultPciInventoryManager:
        # We go over all devices, and we allocate from those that are not
        # in 'alloc_for_pci_class_set'
        # Except that we need to look also at 'network_id', and allocate from
        # the appropriate network bucket.
        # As an optimization we do is the following:
        #   - go over all devices in alloc_for_pci_class_set and temporarily
        #     mark them as 'allocated'
        #   - allocate from all those that are not marked as 'allocated'
        #   - clear the 'allocated' markings

        out_set = None

        try:
            # Mark all the relevant objects as allocated in their buckets
            for pci_dev in alloc_for_pci_class_set:
                network_bucket = self._network_buckets.get(pci_dev.network_id)
                if not network_bucket:
                    net_id = pci_dev.network_id
                    LOG.warn(_("PCI device %(pci_dev)s, network_id %(net_id)s"\
                        " does not have a network bucket!") % locals())
                    # Strange, but forget it
                    continue

                network_bucket.mark_pci_device_allocated(pci_dev)

            # Print
            for network_bucket in self._network_buckets.itervalues():
                network_bucket.print_free_pci_devices()

            # We need to allocate 'count' devices from appropriate network_id
            # We know at this point, that network_id is not None, since we
            # normalized the allocation requirements
            network_bucket = self._network_buckets.get(network_id)
            if network_bucket is not None:
                out_set = network_bucket.allocate_pci_devices(count)
            else:
                LOG.error(_('Network bucket for %(network_id)s not found!')
                    % locals())
            # At this point, out_set is either non-empty or is None

        # Whatever happens, we must clear all the allocations before
        # leaving this function
        finally:
            for network_bucket in self._network_buckets.itervalues():
                network_bucket.clear_allocated()

        return out_set

    def has_network_pci_devices(self, pci_class_set,
                                network, mapping, plugging):
        def _parent_pf_key(pci_dev):
            return pci_dev.parent_pf
        """
        This method is specific to NetVfPciInventoryManager class.
        It checks whether there is at least one PCI device in 'pci_class_set',
        which can serve as a network interface for (network,mapping) pair.
        The method returns True if yes, False otherwise.

        In addition, this method also sets the MAC address of the found PCI
        devices to the required MAC address. So if there is more than one
        such device, all devices will receive the same MAC address, which
        is problematic. In this case, it is expected that the VM will bond all
        these devices into a single network interface.
        Parameters:
            pci_class_set - a set of PciDevice objects
            network,mapping - same as passed to VIFDriver.plug() method
            plugging - whether we are plugging or unplugging the network
            interface
        """
        result = False
        network_label = mapping['label']
        index = 0

        for pci_dev in sorted(pci_class_set, key=_parent_pf_key):
            if pci_dev.network_id == network_label:
                result = True
                LOG.info(_("%(pci_dev)s is suitable for network "\
                           "%(network_label)s") % locals())
                if plugging:
                    self.pci_driver.pci_device_set_mac(pci_dev, 
                                            mapping['mac'], index)
                    index += 1

        return result
