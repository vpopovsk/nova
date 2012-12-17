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
Implementation of nova.virt.pci.PciDriver for libvirt

"""
import os
from nova import exception
from nova import utils
from nova.openstack.common import log as logging
from nova.virt import pci


LOG = logging.getLogger(__name__)

libvirt = None

class LibvirtPciDriver(pci.PciDriver):
    """
    Implements required methods of nova.virt.pci.PciDriver using libvirt
    """

    def __init__(self):
        super(LibvirtPciDriver, self).__init__()

    #############################################################
    # The following methods are abstract within nova.virt.pci.PciDriver
    # and are implemented here
    def init_host_subclass(self, **kwargs):
        self._libvirt_conn = kwargs.get('libvirt_connection')
        if not self._libvirt_conn:
            raise exception.InvalidInput(
                reason='libvirt_connection must be specified to\
                    LibvirtPciDriver::init_host')

    def pci_device_discovery(self):
        raise NotImplementedError()

    def pci_device_init_subclass(self, pci_dev):
        if pci_dev.pci_class != 'net_vf':
            return

        # We need to find the VF number to use with the 'ip' tool
        vf_num = 0
        try:
            while True:
                # Read the value of the symbolic link, like following:
                # /sys/class/net/eth2/device/virtfn0
                # If the symbolic link does not exist, readlink() will raise
                link_value = os.readlink("/sys/class/net/" + \
                                         pci_dev.parent_pf + \
                                         "/device/virtfn" + repr(vf_num))
                # We deal only with uppercase PCI addresses
                link_value = link_value.upper()
                if link_value.endswith(pci_dev.pci_addr):
                    pci_dev.vf_num = vf_num
                    LOG.info(_("%(pci_dev)s, vf_num=%(vf_num)s") % locals())
                    break

                vf_num = vf_num + 1  # Try next vf_num

        except OSError:
            raise exception.PciDeviceSetupError(
                pci_address=pci_dev.pci_addr,
                error="Did not found 'virtfnX' entry; is parent_pf wrong?")

    def pci_device_prepare_for_use(self, pci_dev):
        #global libvirt
        #if libvirt is None:
        #    libvirt = __import__('libvirt')

        # The code below is not needed, in principle, because, as it turns out,
        # libvirt/KVM does all the necessary preparations.
        # So leaving it commented out only as a reference

	return

        # First create a PCI device name in libvirt format: pci_0000_00_04_0
        pci_domain, pci_bus, pci_slot, pci_function = \
            self._pci_addr_split_re.split(pci_dev.pci_addr)
        pci_dev_name_libvirt = 'pci_' + pci_domain + '_' + pci_bus + '_' +\
                               pci_slot + '_' + pci_function

        try:
            # Lookup the device
            # libvirt_dev = \
            #    self._libvirt_conn.nodeDeviceLookupByName(pci_dev_name_libvirt)

            # LOG.info(_("Detaching PCI device: %(pci_dev)s") % locals())
            # libvirt_dev.dettach()  # Note the double-t

            # LOG.info(_("Resetting PCI device: %(pci_dev)s") % locals())
            # libvirt_dev.reset()
            pass
        except libvirt.libvirtError as exc:
            raise exception.PciDeviceSetupError(
                pci_address=pci_dev.pci_addr, error=str(exc))

    def _encode_index_in_mac(self, mac, index):
        # Encode index in higher-order bits of mac
        mac_parts = mac.split(':')
        mac_parts[1] = '%02x' % (int(mac_parts[1], 16) + index)
        return ':'.join(mac_parts)

    def pci_device_set_mac(self, pci_dev, mac, index):
        if pci_dev.pci_class != 'net_vf':
            return

        # See 'man ip' for more information
        mac = self._encode_index_in_mac(mac, index)
        LOG.info(_("%(pci_dev)s, setting encoded(idx-%(index)d) "\
            "MAC: %(mac)s") % locals())
        utils.execute('ip', 'link', 'set', pci_dev.parent_pf,
                      'vf', pci_dev.vf_num, 'mac', mac,
                      run_as_root=True)
