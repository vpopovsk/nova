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

import json
from nova import test
from nova import flags
from nova import exception
from nova import context
from nova import db
from nova.compute import instance_types
from nova.virt import pci
from nova.openstack.common import log as logging

FLAGS = flags.FLAGS
LOG = logging.getLogger('nova.tests.pci')


class TestPciDriver(pci.PciDriver):
    def __init__(self):
        super(TestPciDriver, self).__init__()

    #############################################################
    # The following methods are abstract within nova.virt.pci.PciDriver
    # and are implemented here
    def init_host_subclass(self, **kwargs):
        pass

    def pci_device_discovery(self):
        raise NotImplementedError()

    def pci_device_init_subclass(self, pci_dev):
        pass

    def pci_device_prepare_for_use(self, pci_dev):
        pass

    def pci_device_set_mac(self, pci_dev, mac):
        raise NotImplementedError()


class PciInventoryTestCase(test.TestCase):

    def setUp(self):
        super(PciInventoryTestCase, self).setUp()
        self.pci_driver = TestPciDriver()

    def tearDown(self):
        self.pci_driver = None
        super(PciInventoryTestCase, self).tearDown()

    def test_pci_inventory_static_config_simple_errors(self):
        # Test malformed flags
        FLAGS.pci_devices = ['{"pci_addr": "0010:00:ab.d", "pci_class" :\
        "net_vf", "network_id":"br500", parent_pf:"eth2"}']
        self.assertRaises(exception.InvalidInput, self.pci_driver.init_host,
            "test-host")

        FLAGS.pci_devices = ['{"pci_addr": "0010:00:ab.1", "network_id":\
        "br500, "parent_pf":"eth2"}']
        self.assertRaises(exception.InvalidInput, self.pci_driver.init_host,
            "test-host")

        # Test not having "pci_addr"
        FLAGS.pci_devices = ['{"pci_addr1": "0010:00:ab.d", "pci_class" :\
        "net_vf", "network_id":"br500", "parent_pf":"eth2"}']
        self.assertRaises(exception.InvalidInput, self.pci_driver.init_host,
            "test-host")

        # Test bad PCI address (PCI function must be 0-7)
        FLAGS.pci_devices = ['{"pci_addr": "0010:00:ab.d", "pci_class" : \
        "net_vf", "network_id":"br500", "parent_pf":"eth2"}']
        self.assertRaises(exception.InvalidInput, self.pci_driver.init_host,
            "test-host")

        # Test bad PCI address (. instead of :)
        FLAGS.pci_devices = ['{"pci_addr": "0010.00:ab.3", "pci_class" :\
            "net_vf", "network_id":"br500", "parent_pf":"eth2"}']
        self.assertRaises(exception.InvalidInput, self.pci_driver.init_host,
            "test-host")

        # Test bad PCI address (invalid hex digit)
        FLAGS.pci_devices = ['{"pci_addr": "0g10:00:ab.1", "pci_class" :\
        "net_vf", "network_id":"br500", "parent_pf":"eth2"}']
        self.assertRaises(exception.InvalidInput, self.pci_driver.init_host,
            "test-host")

        # Test bad PCI address (not enough digits in PCI domain)
        FLAGS.pci_devices = ['{"pci_addr": "010:00:ab.1", "pci_class" :\
        "net_vf", "network_id":"br500", "parent_pf":"eth2"}']
        self.assertRaises(exception.InvalidInput, self.pci_driver.init_host,
            "test-host")

        # Test bad PCI address (no PCI domain)
        FLAGS.pci_devices = ['{"pci_addr": "00:ab.1", "pci_class" : "net_vf",\
        "network_id":"br500", "parent_pf":"eth2"}']
        self.assertRaises(exception.InvalidInput, self.pci_driver.init_host,
            "test-host")

        # Test bad PCI address (missing :)
        FLAGS.pci_devices = ['{"pci_addr": "0010 00:ab.1", "pci_class" :\
        "net_vf", "network_id":"br500", "parent_pf":"eth2"}']
        self.assertRaises(exception.InvalidInput, self.pci_driver.init_host,
            "test-host")

        # Test not having "pci_class"
        FLAGS.pci_devices = ['{"pci_addr": "0010:00:ab.1", "network_id":\
            "br500", "parent_pf":"eth2"}']
        self.assertRaises(exception.InvalidInput, self.pci_driver.init_host,
            "test-host")

        # Test adding same device twice (note that after this piece of code,
        # 0010:00:ab.1 and 0010:00:ab.2 are added to the inventory)
        FLAGS.pci_devices = [
            '{"pci_addr": "0010:00:ab.1", "pci_class": "net_vf",\
              "network_id":"br500", "parent_pf":"eth2"}',
            '{"pci_addr": "0010:00:ab.2", "pci_class": "net_vf",\
              "network_id":"br500", "parent_pf":"eth2"}',
            '{"pci_addr": "0010:00:ab.1", "pci_class": "net_vf",\
              "network_id":"br500", "parent_pf":"eth2"}']
        self.assertRaises(exception.Duplicate, self.pci_driver.init_host,
            "test-host")

        # Test not supplying required parameters for net_vf
        FLAGS.pci_devices = ['{"pci_addr": "0010:00:ab.3", "pci_class":\
            "net_vf","network1_id":"br500", "parent_pf":"eth2"}']
        self.assertRaises(exception.InvalidInput, self.pci_driver.init_host,
            "test-host")

        FLAGS.pci_devices = ['{"pci_addr": "0010:00:ab.4", "pci_class": \
            "net_vf","network_id":"br500"}']
        self.assertRaises(exception.InvalidInput, self.pci_driver.init_host,
            "test-host")

    def test_pci_inventory_static_config_complex(self):
        FLAGS.pci_devices = [
        '{"pci_addr": "0010:00:00.1", "pci_class": "net_vf",\
          "network_id":"br500", "parent_pf":"eth0"}',
        '{"pci_addr": "0010:00:00.2", "pci_class": "net_vf",\
          "network_id":"br501", "parent_pf":"eth0"}',
        '{"pci_addr": "0010:00:01.1", "pci_class": "net_vf",\
          "network_id":"br502", "parent_pf":"eth0"}',
        '{"pci_addr": "0010:00:01.2", "pci_class": "net_vf",\
          "network_id":"br500", "parent_pf":"eth0"}',
        '{"pci_addr": "0010:00:02.0", "pci_class": "net_vf",\
          "network_id":"br501", "parent_pf":"eth0"}',
        '{"pci_addr": "0010:01:00.1", "pci_class": "net_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "0010:01:00.2", "pci_class": "net_vf",\
           "network_id":"br500", "parent_pf":"eth1"}',
        '{"pci_addr": "0010:01:01.1", "pci_class": "net_vf",\
          "network_id":"br501", "parent_pf":"eth1"}',
        '{"pci_addr": "0010:01:01.2", "pci_class": "net_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "0010:01:02.0", "pci_class": "net_vf",\
           "network_id":"br500", "parent_pf":"eth1"}',
        '{"pci_addr": "0000:01:00.1", "pci_class": "net_vf",\
          "network_id":"br501", "parent_pf":"eth2"}',
        '{"pci_addr": "0000:01:00.2", "pci_class": "net_vf",\
          "network_id":"br502", "parent_pf":"eth2"}',
        '{"pci_addr": "0000:01:01.1", "pci_class": "net_vf",\
          "network_id":"br500", "parent_pf":"eth2"}',
        '{"pci_addr": "0000:01:01.2", "pci_class": "net_vf",\
          "network_id":"br501", "parent_pf":"eth2"}',
        '{"pci_addr": "0000:01:02.0", "pci_class": "net_vf",\
          "network_id":"br502", "parent_pf":"eth2"}',

        '{"pci_addr": "0000:01:10.0", "pci_class": "sas_vf",\
          "sasparam1":"val1", "sasparam2":"val2"}',
        '{"pci_addr": "0000:01:10.1", "pci_class": "sas_vf",\
          "sasparam1":"val10", "sasparam2":"val20"}']

        self.pci_driver.init_host("test-host")


class PciInstanceTypeTestCase(test.TestCase):

    def setUp(self):
        super(PciInstanceTypeTestCase, self).setUp()
        self.pci_driver = TestPciDriver()

    def tearDown(self):
        self.pci_driver = None
        super(PciInstanceTypeTestCase, self).tearDown()

    def test_pci_allocation_required(self):
        alloc_requirement1 = [
            dict(pci_class='net_vf', count=2, network_id='netXXX')]
        alloc_requirement2 = [
            dict(pci_class='net_vf', count=1),
            dict(pci_class='sas_vf', count=3, sas_param1='sas_val1',
                 sas_param2='sas_val2')]
        alloc_requirement3 = [
            dict(pci_class='net_vf', count=1),
            dict(pci_class='sas_vf', count=3, sas_param1='sasas'),
            dict(pci_class='net_vf', count=2, network_id='br400')]

        instance_types.create('it_no_extra_specs', 1024, 1, 5, 7)
        instance_types.create('it_no_pci_devs', 1024, 1, 5, 8,
            extra_specs=dict(key1='value1'))
        instance_types.create('it_pci_requir1', 2000, 2, 50, 9,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement1)))
        instance_types.create('it_pci_requir2', 4000, 4, 50, 10,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement2)))
        instance_types.create('it_pci_requir3', 4000, 4, 50, 11,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement3)))

        it_no_extra_specs = instance_types.get_instance_type_by_name(
            'it_no_extra_specs')
        it_no_pci_devs = instance_types.get_instance_type_by_name(
            'it_no_pci_devs')
        it_pci_requir1 = instance_types.get_instance_type_by_name(
            'it_pci_requir1')
        it_pci_requir2 = instance_types.get_instance_type_by_name(
            'it_pci_requir2')
        it_pci_requir3 = instance_types.get_instance_type_by_name(
            'it_pci_requir3')

        alloc_req = self.pci_driver._pci_device_allocation_required(
            it_no_extra_specs)
        self.assertIsNone(alloc_req)
        alloc_req = self.pci_driver._pci_device_allocation_required(
            it_no_pci_devs)
        self.assertIsNone(alloc_req)
        alloc_req = self.pci_driver._pci_device_allocation_required(
            it_pci_requir1)
        self.assertDictListMatch(alloc_req, alloc_requirement1)
        alloc_req = self.pci_driver._pci_device_allocation_required(
            it_pci_requir2)
        self.assertDictListMatch(alloc_req, alloc_requirement2)
        alloc_req = self.pci_driver._pci_device_allocation_required(
            it_pci_requir3)
        self.assertDictListMatch(alloc_req, alloc_requirement3)

    def test_pci_allocation_required_errors(self):
        # Malformed
        alloc_requirement_str1 = '[{"pci_class: "net_vf", "count":1]'
        # Not a JSON array
        alloc_requirement_str2 = '{"pci_class": "net_vf", "count":1}'
        # The second element is not a valid JSON object
        alloc_requirement_str3 = '[{"pci_class": "net_vf", "count":1}, \
            ["pci_class", "net_vf"] ]'

        alloc_requirement_str4 = '[{"pci_class": "net_vf", "count":1},\
              {"pci_class1":"sas", "count":2} ]'  # No 'pci_class'
        alloc_requirement_str5 = '[{"pci_class": "net_vf", "count":1}, \
              {"pci_class":"sas", "count1":2} ]'  # No 'count'
        alloc_requirement_str6 = '[{"pci_class": "net_vf", "count":1}, \
              {"pci_class":"sas", "count":"a"} ]'  # 'count' not int
        alloc_requirement_str7 = '[{"pci_class":"sas", "count":1},\
            {"pci_class":"net", "count":-2}]'  # Negative count

        instance_types.create('it1', 1024, 1, 5, 7,
            extra_specs=dict(pci_devices=alloc_requirement_str1))
        instance_types.create('it2', 1024, 1, 5, 8,
            extra_specs=dict(pci_devices=alloc_requirement_str2))
        instance_types.create('it3', 1024, 1, 5, 9,
            extra_specs=dict(pci_devices=alloc_requirement_str3))
        instance_types.create('it4', 1024, 1, 5, 10,
            extra_specs=dict(pci_devices=alloc_requirement_str4))
        instance_types.create('it5', 1024, 1, 5, 11,
            extra_specs=dict(pci_devices=alloc_requirement_str5))
        instance_types.create('it6', 1024, 1, 5, 12,
            extra_specs=dict(pci_devices=alloc_requirement_str6))
        instance_types.create('it7', 1024, 1, 5, 13,
            extra_specs=dict(pci_devices=alloc_requirement_str7))

        it1 = instance_types.get_instance_type_by_name('it1')
        it2 = instance_types.get_instance_type_by_name('it2')
        it3 = instance_types.get_instance_type_by_name('it3')
        it4 = instance_types.get_instance_type_by_name('it4')
        it5 = instance_types.get_instance_type_by_name('it5')
        it6 = instance_types.get_instance_type_by_name('it6')
        it7 = instance_types.get_instance_type_by_name('it7')

        alloc_req = self.pci_driver._pci_device_allocation_required(it1)
        self.assertIsNone(alloc_req)
        alloc_req = self.pci_driver._pci_device_allocation_required(it2)
        self.assertIsNone(alloc_req)
        alloc_req = self.pci_driver._pci_device_allocation_required(it3)
        self.assertIsNone(alloc_req)
        alloc_req = self.pci_driver._pci_device_allocation_required(it4)
        self.assertIsNone(alloc_req)
        alloc_req = self.pci_driver._pci_device_allocation_required(it5)
        self.assertIsNone(alloc_req)
        alloc_req = self.pci_driver._pci_device_allocation_required(it6)
        self.assertIsNone(alloc_req)
        alloc_req = self.pci_driver._pci_device_allocation_required(it7)
        self.assertIsNone(alloc_req)


class PciInstanceMetadataErrorsTestCase(test.TestCase):

    def setUp(self):
        super(PciInstanceMetadataErrorsTestCase, self).setUp()
        self.pci_driver = TestPciDriver()

        FLAGS.pci_devices = [
        '{"pci_addr": "0010:00:00.1", "pci_class": "net_vf",\
          "network_id":"br500", "parent_pf":"eth0"}',
        '{"pci_addr": "0010:00:00.2", "pci_class": "net_vf",\
          "network_id":"br501", "parent_pf":"eth0"}',
        '{"pci_addr": "0010:00:01.1", "pci_class": "net_vf",\
          "network_id":"br502", "parent_pf":"eth0"}',
        '{"pci_addr": "0010:00:01.2", "pci_class": "net_vf",\
          "network_id":"br500", "parent_pf":"eth0"}',
        '{"pci_addr": "0010:00:02.0", "pci_class": "net_vf",\
          "network_id":"br501", "parent_pf":"eth0"}',
        '{"pci_addr": "0010:01:00.1", "pci_class": "net_vf",\
          "network_id":"br502", "parent_pf":"eth1"}']
        self.pci_driver.init_host('test-host')

        ctx = context.get_admin_context()

        values = dict(host='test-host')
        self.i1bad_ref = db.instance_create(ctx, values)

        values = dict(host='test-host', metadata=dict(key1='value1'))
        self.i2bad_ref = db.instance_create(ctx, values)

        values = dict(host='test-host', metadata={
            # Invalid syntax in the pci_devices string
            'pci_devices_test-host': '["0000:00:1e.0" "0000:00:1e.1"}]'})
        self.i3bad_ref = db.instance_create(ctx, values)

        values = dict(host='test-host', metadata={
            # Not a JSON array
            'pci_devices_test-host': '{"0000:00:1e.0": "0000:00:1e.1"}'})
        self.i4bad_ref = db.instance_create(ctx, values)

        values = dict(host='test-host', metadata={
            # PCI devices not in inventory
            'pci_devices_test-host': '["aa", "bb", "0020:01:00.1"]'})
        self.i5bad_ref = db.instance_create(ctx, values)

        values = dict(host='test-host', metadata={
            # PCI devices not in inventory or on a different host
            'pci_devices_test-host2': '["0010:00:00.1"]',
            'pci_devices_test-host': '["aa", "bb", "0020:01:00.1"]'})
        self.i6bad_ref = db.instance_create(ctx, values)

        values = dict(host='test-host', metadata={
            # Empty list of PCI devices???
            'pci_devices_test-host2': '["0010:00:00.1"]',
            'pci_devices_test-host': '[]'})
        self.i7bad_ref = db.instance_create(ctx, values)

    def tearDown(self):
        self.pci_driver = None
        super(PciInstanceMetadataErrorsTestCase, self).tearDown()

    def test_get_allocated_devices_for_instance_errors(self):
        allocated = self.pci_driver._find_allocated_pci_devices_for_instance(
            self.i1bad_ref)
        self.assertDictMatch(allocated, {})

        allocated = self.pci_driver._find_allocated_pci_devices_for_instance(
            self.i2bad_ref)
        self.assertDictMatch(allocated, {})

        allocated = self.pci_driver._find_allocated_pci_devices_for_instance(
            self.i3bad_ref)
        self.assertDictMatch(allocated, {})

        allocated = self.pci_driver._find_allocated_pci_devices_for_instance(
            self.i4bad_ref)
        self.assertDictMatch(allocated, {})

        allocated = self.pci_driver._find_allocated_pci_devices_for_instance(
            self.i5bad_ref)
        self.assertDictMatch(allocated, {})

        allocated = self.pci_driver._find_allocated_pci_devices_for_instance(
            self.i6bad_ref)
        self.assertDictMatch(allocated, {})

        allocated = self.pci_driver._find_allocated_pci_devices_for_instance(
            self.i7bad_ref)
        self.assertDictMatch(allocated, {})


class PciInstanceMetadataTestCase(test.TestCase):

    def setUp(self):
        super(PciInstanceMetadataTestCase, self).setUp()
        self.pci_driver = TestPciDriver()

        # Set up inventory
        FLAGS.pci_devices = [
        '{"pci_addr": "0000:00:1E.0", "pci_class": "net_vf",\
          "network_id":"br500", "parent_pf":"eth0"}',
        '{"pci_addr": "0000:00:1E.2", "pci_class": "sas_vf",\
          "network_id":"br501", "parent_pf":"eth0"}',
        '{"pci_addr": "0000:00:1E.3", "pci_class": "cool_vf",\
          "network_id":"br502", "parent_pf":"eth0"}',
        '{"pci_addr": "0000:00:1E.4", "pci_class": "net_vf",\
          "network_id":"br500", "parent_pf":"eth0"}',
        '{"pci_addr": "0000:00:1E.5", "pci_class": "sas_vf",\
          "network_id":"br501", "parent_pf":"eth0"}',
        '{"pci_addr": "0000:00:1E.6", "pci_class": "cool_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "0000:00:1E.7", "pci_class": "net_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "0000:00:1F.0", "pci_class": "sas_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "0000:00:2E.0", "pci_class": "cool_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "0000:00:2E.1", "pci_class": "net_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "0000:00:5E.0", "pci_class": "sas_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "0000:00:5E.1", "pci_class": "cool_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "0020:00:BA.0", "pci_class": "net_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "0100:00:BA.1", "pci_class": "sas_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "0400:00:3A.0", "pci_class": "cool_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "1020:00:BA.0", "pci_class": "net_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "1100:00:BA.1", "pci_class": "sas_vf",\
          "network_id":"br502", "parent_pf":"eth1"}',
        '{"pci_addr": "1400:00:3A.0", "pci_class": "cool_vf",\
          "network_id":"br502", "parent_pf":"eth1"}']
        self.pci_driver.init_host('test-host')

        self._my_inventory = {}
        for pci_device_str in FLAGS.pci_devices:
            pci_dev_dict = json.loads(pci_device_str)
            pci_addr = pci_dev_dict['pci_addr']
            pci_class = pci_dev_dict['pci_class']
            del pci_dev_dict['pci_addr']
            del pci_dev_dict['pci_class']
            pci_dev = pci.PciDevice(pci_addr, pci_class, **pci_dev_dict)
            self._my_inventory[pci_addr] = pci_dev

        ctx = context.get_admin_context()

        # Create instances in the DB with already-allocated devices
        # Note that the values in DB are always uppercase

        self.i1_values = dict(host="test-host", metadata={
            'pci_devices_test-host': '["0000:00:1E.0"]'})
            # We pass a shallow copy, because instance_create modifies
            # the passed dictionary
        self.i1_ref = db.instance_create(ctx, self.i1_values.copy())

        self.i2_values = dict(host="test-host", metadata={
            'pci_devices_test-host': '["0000:00:1E.2","0000:00:1E.3"]'})
        self.i2_ref = db.instance_create(ctx, self.i2_values.copy())

        self.i3_values = dict(host="test-host", metadata={
            'pci_devices_test-host': '["0000:00:1E.4","0000:00:1E.5",\
             "0000:00:1E.6","0000:00:1E.7","0000:00:1F.0"]'})
        self.i3_ref = db.instance_create(ctx, self.i3_values.copy())

        self.i4_values = dict(host="test-host", metadata={
            'pci_devices_test-host': '["0000:00:2E.0","0000:00:2E.1"]',
            'pci_devices_another-host': '["0000:00:2A.0","0000:00:2A.1",\
                                           "0000:00:3A.0"]'})
        self.i4_ref = db.instance_create(ctx, self.i4_values.copy())

        self.i5_values = dict(host="test-host", metadata={
            'pci_devices_test-host': '["0000:00:5E.0","0000:00:5E.1",\
                                       "0020:00:BA.0","0100:00:BA.1",\
                                       "0400:00:3A.0","1020:00:BA.0",\
                                       "1100:00:BA.1","1400:00:3A.0"]'})
        self.i5_ref = db.instance_create(ctx, self.i5_values.copy())

    def _construct_allocated_from_instance_values(self, values):
        """
        Construct allocated-devices-dict from values used
        during instance creation
        """
        allocated = {}

        pci_devices_str = values['metadata'].get('pci_devices_test-host')
        pci_devices_list = json.loads(pci_devices_str)
        for pci_addr in pci_devices_list:
            pci_dev = self._my_inventory[pci_addr]
            pci_class_set = allocated.get(pci_dev.pci_class)
            if not pci_class_set:
                pci_class_set = set()
                allocated[pci_dev.pci_class] = pci_class_set
            pci_class_set.add(pci_dev)

        return allocated

    def _move_allocated(self, values1, values2):
        """
        Move allocated devices from values2 to values1
        """
        for pci_class, pci_class_set_in2 in values2.iteritems():
            pci_class_set_in1 = values1.get(pci_class)
            if not pci_class_set_in1:
                values1[pci_class] = pci_class_set_in2
            else:
                for pci_addr in pci_class_set_in2:
                    pci_class_set_in1.add(pci_addr)

    def _assert_allocated_equal(self, alloc1, alloc2):
        pci_classes1 = set(alloc1.keys())
        pci_classes2 = set(alloc2.keys())
        self.assertEqual(pci_classes1, pci_classes2)

        for pci_class in pci_classes1:
            pci_devs_set1 = alloc1[pci_class]
            pci_devs_set2 = alloc2[pci_class]
            self.assertEqual(len(pci_devs_set1), len(pci_devs_set2))
            for pci_dev1 in pci_devs_set1:
                found = False
                for pci_dev2 in pci_devs_set2:
                    if pci_dev2.pci_addr == pci_dev1.pci_addr:
                        found = True
                        break
                self.assertTrue(found)
                self.assertEqual(pci_dev1.pci_addr, pci_dev2.pci_addr)
                self.assertEqual(pci_dev1.pci_class, pci_dev2.pci_class)
                self.assertDictMatch(pci_dev1._class_specific_params,\
                                     pci_dev2._class_specific_params)

    def tearDown(self):
        self.pci_driver = None
        super(PciInstanceMetadataTestCase, self).tearDown()

    def test_get_allocated_devices_for_instance(self):
        allocated = self.pci_driver._find_allocated_pci_devices_for_instance(
            self.i1_ref)
        correct_allocated = self._construct_allocated_from_instance_values(
            self.i1_values)
        self._assert_allocated_equal(allocated, correct_allocated)

        allocated = self.pci_driver._find_allocated_pci_devices_for_instance(
            self.i2_ref)
        correct_allocated = self._construct_allocated_from_instance_values(
            self.i2_values)
        self._assert_allocated_equal(allocated, correct_allocated)

        allocated = self.pci_driver._find_allocated_pci_devices_for_instance(
            self.i3_ref)
        correct_allocated = self._construct_allocated_from_instance_values(
            self.i3_values)
        self._assert_allocated_equal(allocated, correct_allocated)

        allocated = self.pci_driver._find_allocated_pci_devices_for_instance(
            self.i4_ref)
        correct_allocated = self._construct_allocated_from_instance_values(
            self.i4_values)
        self._assert_allocated_equal(allocated, correct_allocated)

        allocated = self.pci_driver._find_allocated_pci_devices_for_instance(
            self.i5_ref)
        correct_allocated = self._construct_allocated_from_instance_values(
            self.i5_values)
        self._assert_allocated_equal(allocated, correct_allocated)

    def test_find_allocated_pci_devices(self):
        all_allocated = {}
        self._move_allocated(all_allocated,
            self._construct_allocated_from_instance_values(self.i1_values))
        self._move_allocated(all_allocated,
            self._construct_allocated_from_instance_values(self.i2_values))
        self._move_allocated(all_allocated,
            self._construct_allocated_from_instance_values(self.i3_values))
        self._move_allocated(all_allocated,
            self._construct_allocated_from_instance_values(self.i4_values))
        self._move_allocated(all_allocated,
            self._construct_allocated_from_instance_values(self.i5_values))

        # Give some instance id to the method, it doesn't matter for the test
        found_allocated, dummy = \
            self.pci_driver._find_allocated_pci_devices(777)
        self._assert_allocated_equal(all_allocated, found_allocated)


class PciDeviceAllocationTestCase(test.TestCase):
    def setUp(self):
        super(PciDeviceAllocationTestCase, self).setUp()
        self.pci_driver = TestPciDriver()

        # We have PCI devices of three classes, each class has 8 devices
        self.free_devs_raw = [
            dict(pci_addr="0001:d1:13.0", pci_class="class1",
                class1_param1="cl1_val1"),
            dict(pci_addr="0001:d1:13.1", pci_class="class1",
                class1_param1="cl1_val2"),
            dict(pci_addr="0001:d1:13.2", pci_class="class1",
                class1_param1="cl1_val3"),
            dict(pci_addr="0001:d1:13.3", pci_class="class1",
                class1_param1="cl1_val4"),
            dict(pci_addr="0001:d1:13.4", pci_class="class1",
                class1_param1="cl1_val5"),
            dict(pci_addr="0001:d1:13.5", pci_class="class1",
                class1_param1="cl1_val6"),
            dict(pci_addr="0001:d1:13.6", pci_class="class1",
                class1_param1="cl1_val7"),
            dict(pci_addr="0001:d1:13.7", pci_class="class1",
                class1_param1="cl1_val8"),

            dict(pci_addr="0002:d1:13.0", pci_class="class2",
                class2_param1="cl2_val1"),
            dict(pci_addr="0002:d1:13.1", pci_class="class2",
                class2_param1="cl2_val2"),
            dict(pci_addr="0002:d1:13.2", pci_class="class2",
                class2_param1="cl2_val3"),
            dict(pci_addr="0002:d1:13.3", pci_class="class2",
                class2_param1="cl2_val4"),
            dict(pci_addr="0002:d1:13.4", pci_class="class2",
                class2_param1="cl2_val5"),
            dict(pci_addr="0002:d1:13.5", pci_class="class2",
                class2_param1="cl2_val6"),
            dict(pci_addr="0002:d1:13.6", pci_class="class2",
                class2_param1="cl2_val7"),
            dict(pci_addr="0002:d1:13.7", pci_class="class2",
                class2_param1="cl2_val8"),

            dict(pci_addr="0003:d1:13.0", pci_class="net_vf",
                network_id="net1", parent_pf="eth0"),
            dict(pci_addr="0003:d1:13.1", pci_class="net_vf",
                network_id="net1", parent_pf="eth0"),
            dict(pci_addr="0003:d1:13.2", pci_class="net_vf",
                network_id="net1", parent_pf="eth0"),
            dict(pci_addr="0003:d1:13.3", pci_class="net_vf",
                network_id="net1", parent_pf="eth0"),
            dict(pci_addr="0003:d1:13.4", pci_class="net_vf",
                network_id="net1", parent_pf="eth0"),
            dict(pci_addr="0003:d1:13.5", pci_class="net_vf",
                network_id="net1", parent_pf="eth0"),
            dict(pci_addr="0003:d1:13.6", pci_class="net_vf",
                network_id="net1", parent_pf="eth0"),
            dict(pci_addr="0003:d1:13.7", pci_class="net_vf",
                network_id="net1", parent_pf="eth0")]

        FLAGS.pci_devices = [
            json.dumps(dev_raw) for dev_raw in self.free_devs_raw]
        self.pci_driver.init_host('test-host')

        # Let's also build our own list of PciDevice objects
        self.pci_devs = []
        for dev_raw in self.free_devs_raw:
            class_specific_param = dev_raw.copy()
            del class_specific_param['pci_addr']
            del class_specific_param['pci_class']
            pci_dev = pci.PciDevice(dev_raw['pci_addr'], dev_raw['pci_class'],\
                **class_specific_param)
            self.pci_devs.append(pci_dev)

        # Register instance types
        alloc_requirement1 = [
            {'pci_class': 'class1', 'count':1,
             "class1_param1":"v1"}]  # 1 from class1

        alloc_requirement2 = [
            {'pci_class': 'class2', 'count':1,
             "class2_param1":"v2"}]  # 1 from class2

        alloc_requirement3 = [
            {'pci_class': 'net_vf', 'count':1}]  # 1 from net_vf

        alloc_requirement4 = [
            {'pci_class': 'class2', 'count':2},
            {'pci_class': 'class1', 'count':3}]  # 3 from class1, 2 from class2

        alloc_requirement5 = [
            {'pci_class': 'net_vf', 'count':2},
            {'pci_class': 'class1', 'count':1}]  # 2 from net_vf, 1 from class1

        alloc_requirement6 = [
            {'pci_class': 'class2', 'count':1},
            {'pci_class': 'class1', 'count':1}]  # 1 from class1, 1 from class2

        alloc_requirement7 = [
            {'pci_class': 'class1', 'count':4}]  # 4 from class1

        alloc_requirement8 = [
            # 2 from class1, 1 from class2, 3 from net_vf
            {'pci_class': 'class1', 'count':2},
            {'pci_class': 'class2', 'count':1},
            {'pci_class': 'net_vf', 'count':3}]

        alloc_requirement9 = [
            # 1 from class1, 1 from net_vf, 1 from non-existent class3
            {'pci_class': 'class1', 'count':1},
            {'pci_class': 'net_vf', 'count':1},
            {'pci_class': 'class3', 'count':1}]

        instance_types.create('1_from_1',                      1024, 1, 5, 7,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement1)))
        instance_types.create('1_from_2',                      1024, 1, 5, 8,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement2)))
        instance_types.create('1_from_netvf',                  1024, 1, 5, 9,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement3)))
        instance_types.create('3_from_1_2_from_2',             1024, 1, 5, 10,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement4)))
        instance_types.create('1_from_1_2_from_netvf',         1024, 1, 5, 11,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement5)))
        instance_types.create('1_from_1_1_from_2',             1024, 1, 5, 12,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement6)))
        instance_types.create('4_from_1',                      1024, 1, 5, 13,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement7)))
        instance_types.create('2_from_1_1_from_2_3_from_netvf', 1024, 1, 5, 14,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement8)))
        instance_types.create('1_from_1_1_from_netvf_1_from_class3', 1024, 1, 5, 15,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement9)))

        self.it_1_from_1 = instance_types.get_instance_type_by_name('1_from_1')
        self.it_1_from_2 = instance_types.get_instance_type_by_name('1_from_2')
        self.it_1_from_netvf = instance_types.get_instance_type_by_name(
            '1_from_netvf')
        self.it_3_from_1_2_from_2 = instance_types.get_instance_type_by_name(
            '3_from_1_2_from_2')
        self.it_1_from_1_2_from_netvf = \
            instance_types.get_instance_type_by_name('1_from_1_2_from_netvf')
        self.it_1_from_1_1_from_2 = instance_types.get_instance_type_by_name(
            '1_from_1_1_from_2')
        self.it_4_from_1 = instance_types.get_instance_type_by_name('4_from_1')
        self.it_2_from_1_1_from_2_3_from_netvf = \
            instance_types.get_instance_type_by_name(
                '2_from_1_1_from_2_3_from_netvf')
        self.it_1_from_1_1_from_netvf_1_from_class3 = \
            instance_types.get_instance_type_by_name(
                '1_from_1_1_from_netvf_1_from_class3')

        # These will track allocations during the test
        self.allocs_per_instance = {}
        self.allocs_global = {'class1': 0, 'class2': 0, 'netvf': 0}

    def _assert_valid_pci_dev(self, pci_dev):
        for my_pci_dev in self.pci_devs:
            if pci_dev.pci_addr == my_pci_dev.pci_addr:
                self.assertEqual(pci_dev.pci_class, my_pci_dev.pci_class)
                self.assertDictMatch(pci_dev._class_specific_params,
                                     my_pci_dev._class_specific_params)
                return

        self.assertTrue(False)

    def _update_allocations(self, instance_id,
                            class1_delta, class2_delta, netvf_delta):
        # Update instance entry
        instance_entry = self.allocs_per_instance.get(instance_id)
        if not instance_entry:
            instance_entry = {'class1': 0, 'class2': 0, 'netvf': 0}
            self.allocs_per_instance[instance_id] = instance_entry
        instance_entry['class1'] = instance_entry['class1'] + class1_delta
        instance_entry['class2'] = instance_entry['class2'] + class2_delta
        instance_entry['netvf'] = instance_entry['netvf'] + netvf_delta
        self.assertTrue(instance_entry['class1'] >= 0)
        self.assertTrue(instance_entry['class2'] >= 0)
        self.assertTrue(instance_entry['netvf'] >= 0)
        # Update global allocs
        self.allocs_global['class1'] = self.allocs_global['class1'] +\
            class1_delta
        self.allocs_global['class2'] = self.allocs_global['class2'] +\
            class2_delta
        self.allocs_global['netvf'] = self.allocs_global['netvf'] +\
            netvf_delta
        self.assertTrue(self.allocs_global['class1'] >= 0)
        self.assertTrue(self.allocs_global['class2'] >= 0)
        self.assertTrue(self.allocs_global['netvf'] >= 0)

    def _instance_destroyed(self, instance_id):
        del self.allocs_per_instance[instance_id]

    def _verify_allocations(self, class1, class2, netvf):
        # Verify allocations for instance, global allocations,
        # check for duplicates
        self.assertEqual(self.allocs_global['class1'], class1)
        self.assertEqual(self.allocs_global['class2'], class2)
        self.assertEqual(self.allocs_global['netvf'],  netvf)

        dup_check_set = set()
        allocs_global = {'class1': 0, 'class2': 0, 'netvf': 0}
        allocs_per_instance = {}

        instances = db.instance_get_all_by_host(context.get_admin_context(),
            'test-host')
        for instance in instances:
            instance_dict = \
                self.pci_driver._find_allocated_pci_devices_for_instance(
                    instance)
            if len(instance_dict) == 0:
                continue

            instance_entry = {'class1': 0, 'class2': 0, 'netvf': 0}
            allocs_per_instance[instance['id']] = instance_entry

            class1_set = instance_dict.get('class1')
            if class1_set:
                for pci_dev in class1_set:
                    self._assert_valid_pci_dev(pci_dev)
                    self.assertNotIn(pci_dev, dup_check_set)
                    dup_check_set.add(pci_dev)
                instance_entry['class1'] = len(class1_set)
                allocs_global['class1'] = allocs_global['class1'] +\
                    len(class1_set)

            class2_set = instance_dict.get('class2')
            if class2_set:
                for pci_dev in class2_set:
                    self._assert_valid_pci_dev(pci_dev)
                    self.assertNotIn(pci_dev, dup_check_set)
                    dup_check_set.add(pci_dev)
                instance_entry['class2'] = len(class2_set)
                allocs_global['class2'] = allocs_global['class2'] +\
                    len(class2_set)

            netvf_set = instance_dict.get('net_vf')
            if netvf_set:
                for pci_dev in netvf_set:
                    self._assert_valid_pci_dev(pci_dev)
                    self.assertNotIn(pci_dev, dup_check_set)
                    dup_check_set.add(pci_dev)
                instance_entry['netvf'] = len(netvf_set)
                allocs_global['netvf'] = allocs_global['netvf'] +\
                    len(netvf_set)

        self.assertDictMatch(allocs_per_instance, self.allocs_per_instance)
        self.assertDictMatch(allocs_global, self.allocs_global)

    def tearDown(self):
        self.pci_driver = None
        super(PciDeviceAllocationTestCase, self).tearDown()

    def test_allocate_pci_devices(self):
        ctx = context.get_admin_context()

        # class1: 0, class2: 0, netvf: 0

        i1 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_1['id']))
        self.pci_driver.allocate_pci_devices(i1)
        self._update_allocations(i1['id'], 1, 0, 0)
        self._verify_allocations(1, 0, 0)

        i2 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_2['id']))
        self.pci_driver.allocate_pci_devices(i2)
        self._update_allocations(i2['id'], 0, 1, 0)
        self._verify_allocations(1, 1, 0)

        i3 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_netvf['id']))
        self.pci_driver.allocate_pci_devices(i3)
        self._update_allocations(i3['id'], 0, 0, 1)
        self._verify_allocations(1, 1, 1)

        # Ask to allocate again, and verify that nothing is allocated
        self.pci_driver.allocate_pci_devices(i3)
        self._verify_allocations(1, 1, 1)
        self.pci_driver.allocate_pci_devices(i2)
        self._verify_allocations(1, 1, 1)
        self.pci_driver.allocate_pci_devices(i1)
        self._verify_allocations(1, 1, 1)

        i4 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_3_from_1_2_from_2['id']))
        self.pci_driver.allocate_pci_devices(i4)
        self._update_allocations(i4['id'], 3, 2, 0)
        self._verify_allocations(4, 3, 1)

        i5 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_1_2_from_netvf['id']))
        self.pci_driver.allocate_pci_devices(i5)
        self._update_allocations(i5['id'], 1, 0, 2)
        self._verify_allocations(5, 3, 3)

        i6 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_1_1_from_2['id']))
        self.pci_driver.allocate_pci_devices(i6)
        self._update_allocations(i6['id'], 1, 1, 0)
        self._verify_allocations(6, 4, 3)

        # Ask to allocate again, and verify that nothing is allocated
        self.pci_driver.allocate_pci_devices(i3)
        self._verify_allocations(6, 4, 3)
        self.pci_driver.allocate_pci_devices(i2)
        self._verify_allocations(6, 4, 3)
        self.pci_driver.allocate_pci_devices(i1)
        self._verify_allocations(6, 4, 3)
        self.pci_driver.allocate_pci_devices(i4)
        self._verify_allocations(6, 4, 3)
        self.pci_driver.allocate_pci_devices(i6)
        self._verify_allocations(6, 4, 3)
        self.pci_driver.allocate_pci_devices(i5)
        self._verify_allocations(6, 4, 3)

        # Not enough PCI devices of class1
        i7 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_4_from_1['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i7)
        self._verify_allocations(6, 4, 3)

        # Not enough PCI devicses of class1
        i8 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_3_from_1_2_from_2['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i8)
        self._verify_allocations(6, 4, 3)

        # Let's destroy instance i5, this frees up his allocations
        db.instance_destroy(ctx, i5['id'])
        self._update_allocations(i5['id'], -1, 0, -2)
        self._instance_destroyed(i5['id'])
        self._verify_allocations(5, 4, 1)

        self.pci_driver.allocate_pci_devices(i8)
        self._update_allocations(i8['id'], 3, 2, 0)
        self._verify_allocations(8, 6, 1)

        i9 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_2_from_1_1_from_2_3_from_netvf['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i9)
        self._verify_allocations(8, 6, 1)

        # Ask to allocate again, and verify that nothing is allocated
        self.pci_driver.allocate_pci_devices(i1)
        self._verify_allocations(8, 6, 1)
        self.pci_driver.allocate_pci_devices(i2)
        self._verify_allocations(8, 6, 1)
        self.pci_driver.allocate_pci_devices(i3)
        self._verify_allocations(8, 6, 1)
        self.pci_driver.allocate_pci_devices(i4)
        self._verify_allocations(8, 6, 1)
        self.pci_driver.allocate_pci_devices(i6)
        self._verify_allocations(8, 6, 1)
        self.pci_driver.allocate_pci_devices(i8)
        self._verify_allocations(8, 6, 1)

        i10 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_netvf['id']))
        self.pci_driver.allocate_pci_devices(i10)
        self._update_allocations(i10['id'], 0, 0, 1)
        self._verify_allocations(8, 6, 2)

        # Let's destroy i8 and i1
        db.instance_destroy(ctx, i8['id'])
        self._update_allocations(i8['id'], -3, -2, 0)
        self._instance_destroyed(i8['id'])
        self._verify_allocations(5, 4, 2)

        # Let's destroy i8 and i1
        db.instance_destroy(ctx, i1['id'])
        self._update_allocations(i1['id'], -1, 0, 0)
        self._instance_destroyed(i1['id'])
        self._verify_allocations(4, 4, 2)

        # Now we can allocate for i7
        self.pci_driver.allocate_pci_devices(i7)
        self._update_allocations(i7['id'], 4, 0, 0)
        self._verify_allocations(8, 4, 2)

        # Ask to allocate again, and verify that nothing is allocated
        self.pci_driver.allocate_pci_devices(i2)
        self._verify_allocations(8, 4, 2)
        self.pci_driver.allocate_pci_devices(i3)
        self._verify_allocations(8, 4, 2)
        self.pci_driver.allocate_pci_devices(i4)
        self._verify_allocations(8, 4, 2)
        self.pci_driver.allocate_pci_devices(i6)
        self._verify_allocations(8, 4, 2)
        self.pci_driver.allocate_pci_devices(i10)
        self._verify_allocations(8, 4, 2)

        # Let's destroy i7
        db.instance_destroy(ctx, i7['id'])
        self._update_allocations(i7['id'], -4, 0, 0)
        self._instance_destroyed(i7['id'])
        self._verify_allocations(4, 4, 2)

        # Now we can allocate for i9
        self.pci_driver.allocate_pci_devices(i9)
        self._update_allocations(i9['id'], 2, 1, 3)
        self._verify_allocations(6, 5, 5)

        # Ask to allocate again, and verify that nothing is allocated
        self.pci_driver.allocate_pci_devices(i2)
        self._verify_allocations(6, 5, 5)
        self.pci_driver.allocate_pci_devices(i3)
        self._verify_allocations(6, 5, 5)
        self.pci_driver.allocate_pci_devices(i4)
        self._verify_allocations(6, 5, 5)
        self.pci_driver.allocate_pci_devices(i6)
        self._verify_allocations(6, 5, 5)
        self.pci_driver.allocate_pci_devices(i9)
        self._verify_allocations(6, 5, 5)
        self.pci_driver.allocate_pci_devices(i10)
        self._verify_allocations(6, 5, 5)

    def test_allocate_pci_devices_non_existent_class3(self):
        ctx = context.get_admin_context()

        # class1: 0, class2: 0, netvf: 0

        # Verify that allocation fails
        i1 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_1_1_from_netvf_1_from_class3['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed, self.pci_driver.allocate_pci_devices, i1)
        self._verify_allocations(0, 0, 0)


    def test_partial_allocation1(self):
        ctx = context.get_admin_context()

        i_values = {'host': 'test-host',
                    'instance_type_id': self.it_1_from_1_1_from_2['id'],
                    'metadata': {'pci_devices_test-host': '["0001:d1:13.0"]'}}
        i = db.instance_create(ctx, i_values)
        i['instance_type']  # Need to do a lazy load here
        self._update_allocations(i['id'], 1, 0, 0)
        self._verify_allocations(1, 0, 0)

        self.pci_driver.allocate_pci_devices(i)
        self._update_allocations(i['id'], 0, 1, 0)
        self._verify_allocations(1, 1, 0)

        self.pci_driver.allocate_pci_devices(i)
        self._verify_allocations(1, 1, 0)

    def test_partial_allocation2(self):
        ctx = context.get_admin_context()

        i_values = {'host': 'test-host',
            'instance_type_id': self.it_4_from_1['id'],
            'metadata':
                {'pci_devices_test-host': '["0001:d1:13.0","0001:d1:13.1"]'}}
        i = db.instance_create(ctx, i_values)
        i['instance_type']  # Need to do a lazy load here
        self._update_allocations(i['id'], 2, 0, 0)
        self._verify_allocations(2, 0, 0)

        self.pci_driver.allocate_pci_devices(i)
        self._update_allocations(i['id'], 2, 0, 0)
        self._verify_allocations(4, 0, 0)

        self.pci_driver.allocate_pci_devices(i)
        self._verify_allocations(4, 0, 0)

    def test_partial_allocation3(self):
        ctx = context.get_admin_context()

        i_values = {'host': 'test-host',
            'instance_type_id': self.it_1_from_1_2_from_netvf['id'],
            'metadata':
                {'pci_devices_test-host': '["0003:d1:13.0"]'}}
        i = db.instance_create(ctx, i_values)
        i['instance_type']  # Need to do a lazy load here
        self._update_allocations(i['id'], 0, 0, 1)
        self._verify_allocations(0, 0, 1)

        self.pci_driver.allocate_pci_devices(i)
        self._update_allocations(i['id'], 1, 0, 1)
        self._verify_allocations(1, 0, 2)

        self.pci_driver.allocate_pci_devices(i)
        self._verify_allocations(1, 0, 2)

    def test_partial_allocation4(self):
        ctx = context.get_admin_context()

        i_values = {'host': 'test-host',
            'instance_type_id': self.it_2_from_1_1_from_2_3_from_netvf['id'],
            'metadata':
                {'pci_devices_test-host': '["0001:d1:13.0", "0003:d1:13.0"]'}}
        i = db.instance_create(ctx, i_values)
        i['instance_type']  # Need to do a lazy load here
        self._update_allocations(i['id'], 1, 0, 1)
        self._verify_allocations(1, 0, 1)

        self.pci_driver.allocate_pci_devices(i)
        self._update_allocations(i['id'], 1, 1, 2)
        self._verify_allocations(2, 1, 3)

        self.pci_driver.allocate_pci_devices(i)
        self._verify_allocations(2, 1, 3)

    def test_partial_allocation5(self):
        ctx = context.get_admin_context()

        # Here the instance has allocated more than it needs to and also
        # some devices from non-needed classes

        i_values = {'host': 'test-host',
            'instance_type_id': self.it_1_from_1['id'],
            'metadata': {'pci_devices_test-host':
                '["0001:d1:13.0","0001:d1:13.1","0003:d1:13.0"]'}}
        i = db.instance_create(ctx, i_values)
        i['instance_type']  # Need to do a lazy load here
        self._update_allocations(i['id'], 2, 0, 1)
        self._verify_allocations(2, 0, 1)

        self.pci_driver.allocate_pci_devices(i)
        self._verify_allocations(2, 0, 1)


class NetVfPciDeviceAllocationTestCase(test.TestCase):
    def setUp(self):
        super(NetVfPciDeviceAllocationTestCase, self).setUp()
        self.pci_driver = TestPciDriver()

        # We have 3 networks, each has 8 PCI 'net_vf' devices
        self.free_devs_raw = [
            pci.PciDevice('b500:00:00.1', 'net_vf',
                          network_id='br500', parent_pf='eth0'),
            pci.PciDevice('b500:00:00.2', 'net_vf',
                          network_id='br500', parent_pf='eth0'),
            pci.PciDevice('b500:00:00.3', 'net_vf',
                          network_id='br500', parent_pf='eth1'),
            pci.PciDevice('b500:00:00.4', 'net_vf',
                          network_id='br500', parent_pf='eth1'),
            pci.PciDevice('b500:0A:00.1', 'net_vf',
                          network_id='br500', parent_pf='eth0'),
            pci.PciDevice('b500:0A:00.2', 'net_vf',
                          network_id='br500', parent_pf='eth0'),
            pci.PciDevice('b500:0A:00.3', 'net_vf',
                          network_id='br500', parent_pf='eth1'),
            pci.PciDevice('b500:0A:00.4', 'net_vf',
                          network_id='br500', parent_pf='eth1'),

            pci.PciDevice('b501:00:01.1', 'net_vf',
                          network_id='br501', parent_pf='eth2'),
            pci.PciDevice('b501:00:01.2', 'net_vf',
                          network_id='br501', parent_pf='eth2'),
            pci.PciDevice('b501:00:01.3', 'net_vf',
                          network_id='br501', parent_pf='eth3'),
            pci.PciDevice('b501:00:01.4', 'net_vf',
                          network_id='br501', parent_pf='eth4'),
            pci.PciDevice('b501:0B:01.1', 'net_vf',
                          network_id='br501', parent_pf='eth2'),
            pci.PciDevice('b501:0B:01.2', 'net_vf',
                          network_id='br501', parent_pf='eth2'),
            pci.PciDevice('b501:0B:01.3', 'net_vf',
                          network_id='br501', parent_pf='eth3'),
            pci.PciDevice('b501:0B:01.4', 'net_vf',
                          network_id='br501', parent_pf='eth4'),

            pci.PciDevice('b502:0C:02.1', 'net_vf',
                          network_id='br502', parent_pf='eth5'),
            pci.PciDevice('b502:0C:02.2', 'net_vf',
                          network_id='br502', parent_pf='eth5'),
            pci.PciDevice('b502:0C:02.3', 'net_vf',
                          network_id='br502', parent_pf='eth6'),
            pci.PciDevice('b502:0C:02.4', 'net_vf',
                          network_id='br502', parent_pf='eth6'),
            pci.PciDevice('b502:0D:02.1', 'net_vf',
                          network_id='br502', parent_pf='eth5'),
            pci.PciDevice('b502:0D:02.2', 'net_vf',
                          network_id='br502', parent_pf='eth5'),
            pci.PciDevice('b502:0D:02.3', 'net_vf',
                          network_id='br502', parent_pf='eth6'),
            pci.PciDevice('b502:0D:02.4', 'net_vf',
                          network_id='br502', parent_pf='eth6')]

        # Generate the FLAGS.pci_devices value and initialize the inventory
        FLAGS.pci_devices = [
            json.dumps(dict(pci_addr=pci_dev.pci_addr,
                            pci_class=pci_dev.pci_class,
                            network_id=pci_dev.network_id,
                            parent_pf=pci_dev.parent_pf))
              for pci_dev in self.free_devs_raw]
        self.pci_driver.init_host('test-host')

        # Register simple instance types (where each
        # PCI class appears only once)
        alloc_requirement1 = [{'pci_class': 'net_vf', 'count':1}]  # 1 from all

        alloc_requirement2 = [{'pci_class': 'net_vf', 'count':2}]  # 2 from all

        alloc_requirement3 = [{'pci_class': 'net_vf', 'count':1,
                               'network_id':'br500'}]  # 1 from br500

        alloc_requirement4 = [{'pci_class': 'net_vf', 'count':2,
                               'network_id':'br500'}]  # 2 from br500

        alloc_requirement5 = [{'pci_class': 'net_vf', 'count':1,
                               'network_id':'br501'}]  # 1 from br501

        alloc_requirement6 = [{'pci_class': 'net_vf', 'count':2,
                               'network_id':'br501'}]  # 2 from br501

        alloc_requirement7 = [{'pci_class': 'net_vf', 'count':1,
                               'network_id':'br502'}]  # 1 from br502

        alloc_requirement8 = [{'pci_class': 'net_vf', 'count':2,
                               'network_id':'br502'}]  # 2 from br502

        instance_types.create('1_from_all',   1024, 1, 5, 7,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement1)))
        instance_types.create('2_from_all',   1024, 1, 5, 8,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement2)))
        instance_types.create('1_from_br500', 1024, 1, 5, 9,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement3)))
        instance_types.create('2_from_br500', 1024, 1, 5, 10,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement4)))
        instance_types.create('1_from_br501', 1024, 1, 5, 11,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement5)))
        instance_types.create('2_from_br501', 1024, 1, 5, 12,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement6)))
        instance_types.create('1_from_br502', 1024, 1, 5, 13,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement7)))
        instance_types.create('2_from_br502', 1024, 1, 5, 14,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement8)))
        self.it_1_from_all = instance_types.get_instance_type_by_name(
            '1_from_all')
        self.it_2_from_all = instance_types.get_instance_type_by_name(
            '2_from_all')
        self.it_1_from_br500 = instance_types.get_instance_type_by_name(
            '1_from_br500')
        self.it_2_from_br500 = instance_types.get_instance_type_by_name(
            '2_from_br500')
        self.it_1_from_br501 = instance_types.get_instance_type_by_name(
            '1_from_br501')
        self.it_2_from_br501 = instance_types.get_instance_type_by_name(
            '2_from_br501')
        self.it_1_from_br502 = instance_types.get_instance_type_by_name(
            '1_from_br502')
        self.it_2_from_br502 = instance_types.get_instance_type_by_name(
            '2_from_br502')

        # Register more complex instance types (same PCI class
        # appears more than once)
        alloc_requirement1 = [{'pci_class': 'net_vf', 'count':1},
                              {'pci_class': 'net_vf', 'count':1}]  # 2 from all

        alloc_requirement2 = [
            {'pci_class': 'net_vf', 'count':1, 'network_id':'br500'},
            {'pci_class': 'net_vf', 'count':1,
             'network_id':'br502'}]  # 1 from br500, 1 from br502

        alloc_requirement3 = [
            {'pci_class': 'net_vf', 'count':2, 'network_id':'br501'},
            {'pci_class': 'net_vf', 'count':1, 'network_id':'br502'},
            {'pci_class': 'net_vf', 'count':1,
             'network_id':'br501'}]  # 3 from br501, 1 from br502

        # One from br502, 2 from all (so 3 from br502, 2 from the rest)
        alloc_requirement4 = [
            {'pci_class': 'net_vf', 'count':1, 'network_id':'br502'},
            {'pci_class': 'net_vf', 'count':2}]

        # Requests 2 PCI devices from non-existent network_id
        alloc_requirement5 = [
            {'pci_class': 'net_vf', 'count':1,'network_id':'br501'},
            {'pci_class': 'net_vf', 'count':1},
            {'pci_class': 'net_vf', 'count':2,'network_id':'br777'}]

        instance_types.create('2_from_all_complex',        1024, 1, 5, 15,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement1)))
        instance_types.create('1_from_br500_1_from_br502', 1024, 1, 5, 16,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement2)))
        instance_types.create('3_from_br501_1_from_br502', 1024, 1, 5, 17,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement3)))
        instance_types.create('3_from_br502_2_from_rest',  1024, 1, 5, 18,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement4)))
        instance_types.create('non_existent_network_id',  1024, 1, 5, 19,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement5)))
        self.it_2_from_all_complex = instance_types.get_instance_type_by_name(
            '2_from_all_complex')
        self.it_1_from_br500_1_from_br502 = \
            instance_types.get_instance_type_by_name(
                '1_from_br500_1_from_br502')
        self.it_3_from_br501_1_from_br502 = \
            instance_types.get_instance_type_by_name(
                '3_from_br501_1_from_br502')
        self.it_3_from_br502_2_from_rest = \
            instance_types.get_instance_type_by_name(
                '3_from_br502_2_from_rest')
        self.it_non_existent_network_id = \
            instance_types.get_instance_type_by_name('non_existent_network_id')

        # These will track allocations during the test
        self.allocs_per_instance = {}
        self.allocs_global = {'br500': 0, 'br501': 0, 'br502': 0}

    def _assert_valid_pci_dev(self, pci_dev):
        for my_pci_dev in self.free_devs_raw:
            if pci_dev.pci_addr == my_pci_dev.pci_addr:
                self.assertEqual(pci_dev.pci_class, my_pci_dev.pci_class)
                self.assertDictMatch(pci_dev._class_specific_params,
                                     my_pci_dev._class_specific_params)
                return

        self.assertTrue(False)

    def _update_allocations(self, instance_id,
                            br500_delta, br501_delta, br502_delta):
        # Update instance entry
        instance_entry = self.allocs_per_instance.get(instance_id)
        if not instance_entry:
            instance_entry = {'br500': 0, 'br501': 0, 'br502': 0}
            self.allocs_per_instance[instance_id] = instance_entry
        instance_entry['br500'] = instance_entry['br500'] + br500_delta
        instance_entry['br501'] = instance_entry['br501'] + br501_delta
        instance_entry['br502'] = instance_entry['br502'] + br502_delta
        self.assertTrue(instance_entry['br500'] >= 0)
        self.assertTrue(instance_entry['br501'] >= 0)
        self.assertTrue(instance_entry['br502'] >= 0)
        # Update global allocs
        self.allocs_global['br500'] = self.allocs_global['br500'] + br500_delta
        self.allocs_global['br501'] = self.allocs_global['br501'] + br501_delta
        self.allocs_global['br502'] = self.allocs_global['br502'] + br502_delta
        self.assertTrue(self.allocs_global['br500'] >= 0)
        self.assertTrue(self.allocs_global['br501'] >= 0)
        self.assertTrue(self.allocs_global['br502'] >= 0)

    def _instance_destroyed(self, instance_id):
        del self.allocs_per_instance[instance_id]

    def _verify_allocations(self, br500, br501, br502):
        # Verify allocations for instance, global allocations,
        # check for duplicates
        self.assertEqual(self.allocs_global['br500'], br500)
        self.assertEqual(self.allocs_global['br501'], br501)
        self.assertEqual(self.allocs_global['br502'], br502)

        dup_check_set = set()
        allocs_global = {'br500': 0, 'br501': 0, 'br502': 0}
        allocs_per_instance = {}

        instances = db.instance_get_all_by_host(context.get_admin_context(),
            'test-host')
        for instance in instances:
            instance_dict = \
                self.pci_driver._find_allocated_pci_devices_for_instance(
                    instance)
            self.assertTrue(len(instance_dict) == 1 or len(instance_dict) == 0)
            if len(instance_dict) == 0:
                continue

            instance_entry = {'br500': 0, 'br501': 0, 'br502': 0}
            allocs_per_instance[instance['id']] = instance_entry

            net_vf_set = instance_dict['net_vf']
            for pci_dev in net_vf_set:
                self._assert_valid_pci_dev(pci_dev)
                # Duplicates check
                self.assertNotIn(pci_dev, dup_check_set)
                dup_check_set.add(pci_dev)

                # Update per-instance and global allocations
                instance_entry[pci_dev.network_id] = \
                    instance_entry[pci_dev.network_id] + 1
                allocs_global[pci_dev.network_id] = \
                    allocs_global[pci_dev.network_id] + 1

        self.assertDictMatch(allocs_per_instance, self.allocs_per_instance)
        self.assertDictMatch(allocs_global, self.allocs_global)

    def tearDown(self):
        self.pci_driver = None
        super(NetVfPciDeviceAllocationTestCase, self).tearDown()

    def test_allocate_pci_devices(self):
        ctx = context.get_admin_context()

        # br500: 0, br501: 0, br502: 0

        i1 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_all['id']))
        self.pci_driver.allocate_pci_devices(i1)
        self._update_allocations(i1['id'], 1, 1, 1)
        self._verify_allocations(1, 1, 1)

        i2 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_2_from_br502['id']))
        self.pci_driver.allocate_pci_devices(i2)
        self._update_allocations(i2['id'], 0, 0, 2)
        self._verify_allocations(1, 1, 3)

        i3 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_br502['id']))
        self.pci_driver.allocate_pci_devices(i3)
        self._update_allocations(i3['id'], 0, 0, 1)
        self._verify_allocations(1, 1, 4)

        # Ask to allocate again and verify that nothing gets allocated
        self.pci_driver.allocate_pci_devices(i2)
        self._verify_allocations(1, 1, 4)
        self.pci_driver.allocate_pci_devices(i3)
        self._verify_allocations(1, 1, 4)
        self.pci_driver.allocate_pci_devices(i1)
        self._verify_allocations(1, 1, 4)

        i4 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_2_from_all['id']))
        self.pci_driver.allocate_pci_devices(i4)
        self._update_allocations(i4['id'], 2, 2, 2)
        self._verify_allocations(3, 3, 6)

        i5 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_br502['id']))
        self.pci_driver.allocate_pci_devices(i5)
        self._update_allocations(i5['id'], 0, 0, 1)
        self._verify_allocations(3, 3, 7)

        i6 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_br500['id']))
        self.pci_driver.allocate_pci_devices(i6)
        self._update_allocations(i6['id'], 1, 0, 0)
        self._verify_allocations(4, 3, 7)

        # Ask to allocate again and verify that nothing gets allocated
        self.pci_driver.allocate_pci_devices(i4)
        self._verify_allocations(4, 3, 7)
        self.pci_driver.allocate_pci_devices(i2)
        self._verify_allocations(4, 3, 7)
        self.pci_driver.allocate_pci_devices(i3)
        self._verify_allocations(4, 3, 7)
        self.pci_driver.allocate_pci_devices(i1)
        self._verify_allocations(4, 3, 7)
        self.pci_driver.allocate_pci_devices(i5)
        self._verify_allocations(4, 3, 7)
        self.pci_driver.allocate_pci_devices(i6)
        self._verify_allocations(4, 3, 7)

        i7 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_2_from_br501['id']))
        self.pci_driver.allocate_pci_devices(i7)
        self._update_allocations(i7['id'], 0, 2, 0)
        self._verify_allocations(4, 5, 7)

        i8 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_2_from_br500['id']))
        self.pci_driver.allocate_pci_devices(i8)
        self._update_allocations(i8['id'], 2, 0, 0)
        self._verify_allocations(6, 5, 7)

        i9 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_2_from_all['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i9)
        self._verify_allocations(6, 5, 7)

        # Delete instance 5, it allocated 1 device from br502,
        # then we can allocate for i9
        db.instance_destroy(ctx, i5['id'])
        self._update_allocations(i5['id'], 0, 0, -1)
        self._instance_destroyed(i5['id'])
        self._verify_allocations(6, 5, 6)

        self.pci_driver.allocate_pci_devices(i9)
        self._update_allocations(i9['id'], 2, 2, 2)
        self._verify_allocations(8, 7, 8)

        # Ask to allocate again and verify that nothing gets allocated
        self.pci_driver.allocate_pci_devices(i1)
        self._verify_allocations(8, 7, 8)
        self.pci_driver.allocate_pci_devices(i2)
        self._verify_allocations(8, 7, 8)
        self.pci_driver.allocate_pci_devices(i3)
        self._verify_allocations(8, 7, 8)
        self.pci_driver.allocate_pci_devices(i4)
        self._verify_allocations(8, 7, 8)
        self.pci_driver.allocate_pci_devices(i6)
        self._verify_allocations(8, 7, 8)
        self.pci_driver.allocate_pci_devices(i7)
        self._verify_allocations(8, 7, 8)
        self.pci_driver.allocate_pci_devices(i8)
        self._verify_allocations(8, 7, 8)
        self.pci_driver.allocate_pci_devices(i9)

        # Verify that we indeed cannot allocate from br500 and from br502
        # Needs one from br500
        itmp1 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_br500['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, itmp1)
        # Needs one from br502
        itmp2 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_br502['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, itmp2)
        self._verify_allocations(8, 7, 8)

        # Verify that we cannot allocate 2 from br501
        i10 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_2_from_br501['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i10)
        self._verify_allocations(8, 7, 8)

        # ... but we can allocate 1 from br501
        i11 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_br501['id']))
        self.pci_driver.allocate_pci_devices(i11)
        self._update_allocations(i11['id'], 0, 1, 0)
        self._verify_allocations(8, 8, 8)

        # Ask to allocate again and verify that nothing gets allocated
        self.pci_driver.allocate_pci_devices(i1)
        self._verify_allocations(8, 8, 8)
        self.pci_driver.allocate_pci_devices(i2)
        self._verify_allocations(8, 8, 8)
        self.pci_driver.allocate_pci_devices(i3)
        self._verify_allocations(8, 8, 8)
        self.pci_driver.allocate_pci_devices(i4)
        self._verify_allocations(8, 8, 8)
        self.pci_driver.allocate_pci_devices(i6)
        self._verify_allocations(8, 8, 8)
        self.pci_driver.allocate_pci_devices(i7)
        self._verify_allocations(8, 8, 8)
        self.pci_driver.allocate_pci_devices(i8)
        self._verify_allocations(8, 8, 8)
        self.pci_driver.allocate_pci_devices(i9)
        self._verify_allocations(8, 8, 8)
        self.pci_driver.allocate_pci_devices(i11)
        self._verify_allocations(8, 8, 8)

    def test_allocate_pci_devices_complex(self):
        ctx = context.get_admin_context()

        # br500: 0, br501: 0, br502: 0

        i1 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_2_from_all_complex['id']))
        self.pci_driver.allocate_pci_devices(i1)
        self._update_allocations(i1['id'], 2, 2, 2)
        self._verify_allocations(2, 2, 2)

        i2 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_br500_1_from_br502['id']))
        self.pci_driver.allocate_pci_devices(i2)
        self._update_allocations(i2['id'], 1, 0, 1)
        self._verify_allocations(3, 2, 3)

        i3 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_3_from_br501_1_from_br502['id']))
        self.pci_driver.allocate_pci_devices(i3)
        self._update_allocations(i3['id'], 0, 3, 1)
        self._verify_allocations(3, 5, 4)

        i4 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_3_from_br502_2_from_rest['id']))
        self.pci_driver.allocate_pci_devices(i4)
        self._update_allocations(i4['id'], 2, 2, 3)
        self._verify_allocations(5, 7, 7)

        # Ask to allocate again and verify that nothing gets allocated
        self.pci_driver.allocate_pci_devices(i1)
        self._verify_allocations(5, 7, 7)
        self.pci_driver.allocate_pci_devices(i2)
        self._verify_allocations(5, 7, 7)
        self.pci_driver.allocate_pci_devices(i3)
        self._verify_allocations(5, 7, 7)
        self.pci_driver.allocate_pci_devices(i4)
        self._verify_allocations(5, 7, 7)

    def test_partial_allocation1(self):
        ctx = context.get_admin_context()

        i_values = {'host': 'test-host',
            'instance_type_id': self.it_3_from_br502_2_from_rest['id'],
            'metadata': {'pci_devices_test-host':
                '["b502:0C:02.1","b502:0C:02.2","b501:00:01.1"]'}}
        i = db.instance_create(ctx, i_values)
        i['instance_type']  # Need to do a lazy load here
        self._update_allocations(i['id'], 0, 1, 2)
        self._verify_allocations(0, 1, 2)

        self.pci_driver.allocate_pci_devices(i)
        self._update_allocations(i['id'], 2, 1, 1)
        self._verify_allocations(2, 2, 3)

        self.pci_driver.allocate_pci_devices(i)
        self._verify_allocations(2, 2, 3)

    def test_partial_allocation2(self):
        ctx = context.get_admin_context()

        # Instance has allocated more than needed
        i_values = {'host': 'test-host',
            'instance_type_id': self.it_3_from_br502_2_from_rest['id'],
            'metadata': {'pci_devices_test-host':
                '["b501:00:01.1","b501:00:01.2","b501:00:01.3"]'}}
        i = db.instance_create(ctx, i_values)
        i['instance_type']  # Need to do a lazy load here
        self._update_allocations(i['id'], 0, 3, 0)
        self._verify_allocations(0, 3, 0)

        self.pci_driver.allocate_pci_devices(i)
        self._update_allocations(i['id'], 2, 0, 3)
        self._verify_allocations(2, 3, 3)

        self.pci_driver.allocate_pci_devices(i)
        self._verify_allocations(2, 3, 3)

    def test_non_existent_network_id(self):
        ctx = context.get_admin_context()

        # br500: 0, br501: 0, br502: 0

        i1 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_non_existent_network_id['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i1)
        self._verify_allocations(0, 0, 0)


class EmptyPciInventoryTestCase(test.TestCase):
    def setUp(self):
        super(EmptyPciInventoryTestCase, self).setUp()
        self.pci_driver = TestPciDriver()

        # Empty inventory
        FLAGS.pci_devices = []
        self.pci_driver.init_host('test-host')

        # Register simple instance types (where each
        # PCI class appears only once)
        alloc_requirement1 = [{'pci_class': 'net_vf', 'count':1}]  # 1 from all

        alloc_requirement2 = [{'pci_class': 'net_vf', 'count':2}]  # 2 from all

        alloc_requirement3 = [{'pci_class': 'net_vf', 'count':1,
                               'network_id':'br500'}]  # 1 from br500

        alloc_requirement4 = [{'pci_class': 'net_vf', 'count':2,
                               'network_id':'br500'}]  # 2 from br500

        instance_types.create('1_from_all',   1024, 1, 5, 7,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement1)))
        instance_types.create('2_from_all',   1024, 1, 5, 8,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement2)))
        instance_types.create('1_from_br500', 1024, 1, 5, 9,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement3)))
        instance_types.create('2_from_br500', 1024, 1, 5, 10,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement4)))
        self.it_1_from_all = instance_types.get_instance_type_by_name(
            '1_from_all')
        self.it_2_from_all = instance_types.get_instance_type_by_name(
            '2_from_all')
        self.it_1_from_br500 = instance_types.get_instance_type_by_name(
            '1_from_br500')
        self.it_2_from_br500 = instance_types.get_instance_type_by_name(
            '2_from_br500')

        # Register more complex instance types (same PCI class
        # appears more than once)
        alloc_requirement1 = [{'pci_class': 'net_vf', 'count':1},
                              {'pci_class': 'net_vf', 'count':1}]  # 2 from all

        alloc_requirement2 = [
            {'pci_class': 'net_vf', 'count':1, 'network_id':'br500'},
            {'pci_class': 'net_vf', 'count':1,
             'network_id':'br502'}]  # 1 from br500, 1 from br502

        alloc_requirement3 = [
            {'pci_class': 'net_vf', 'count':2, 'network_id':'br501'},
            {'pci_class': 'net_vf', 'count':1, 'network_id':'br502'},
            {'pci_class': 'net_vf', 'count':1,
             'network_id':'br501'}]  # 3 from br501, 1 from br502

        # One from br502, 2 from all (so 3 from br502, 2 from the rest)
        alloc_requirement4 = [
            {'pci_class': 'net_vf', 'count':1, 'network_id':'br502'},
            {'pci_class': 'net_vf', 'count':2}]

        instance_types.create('2_from_all_complex',        1024, 1, 5, 15,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement1)))
        instance_types.create('1_from_br500_1_from_br502', 1024, 1, 5, 16,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement2)))
        instance_types.create('3_from_br501_1_from_br502', 1024, 1, 5, 17,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement3)))
        instance_types.create('3_from_br502_2_from_rest',  1024, 1, 5, 18,
            extra_specs=dict(pci_devices=json.dumps(alloc_requirement4)))
        self.it_2_from_all_complex = instance_types.get_instance_type_by_name(
            '2_from_all_complex')
        self.it_1_from_br500_1_from_br502 = \
            instance_types.get_instance_type_by_name(
                '1_from_br500_1_from_br502')
        self.it_3_from_br501_1_from_br502 = \
            instance_types.get_instance_type_by_name(
                '3_from_br501_1_from_br502')
        self.it_3_from_br502_2_from_rest = \
            instance_types.get_instance_type_by_name(
                '3_from_br502_2_from_rest')

    def tearDown(self):
        self.pci_driver = None
        super(EmptyPciInventoryTestCase, self).tearDown()

    def test_alloc_failures_from_empty_inventory(self):
        ctx = context.get_admin_context()

        i1 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_all['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i1);
        
        i2 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_2_from_all['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i2);

        i3 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_br500['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i3);

        i4 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_2_from_br500['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i4);

        i5 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_2_from_all_complex['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i5);

        i6 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_1_from_br500_1_from_br502['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i6);

        i7 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_3_from_br501_1_from_br502['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i7);

        i8 = db.instance_create(ctx, values=dict(host='test-host',
            instance_type_id=self.it_3_from_br502_2_from_rest['id']))
        self.assertRaises(exception.PciDeviceAllocationFailed,
            self.pci_driver.allocate_pci_devices, i8);
