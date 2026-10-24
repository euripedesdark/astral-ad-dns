import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


class DirectoryTests(unittest.TestCase):
    def run_directory(self,old_options,gc=True,reference_present=False):
        changes=[]
        class Message(dict):pass
        class Element:
            def __init__(self,value,*_):self.value=value
        class Dn(str):pass
        class Partition(dict):
            dn='CN=DomainDnsZones,CN=Partitions,CN=Configuration,DC=example,DC=test'
        class Database:
            def __init__(self,**_):pass
            def get_schema_basedn(self):return 'schema'
            def get_config_basedn(self):return 'configuration'
            def get_default_basedn(self):return 'DC=example,DC=test'
            def search(self,base,scope,attrs,**_):
                if base=='schema':return [{'objectVersion':[b'88']}]
                if base=='':return [{'dsServiceName':[b'CN=NTDS Settings,CN=SECONDARY,CN=Servers,CN=Configuration,DC=example,DC=test']}]
                if attrs==['options']:return [{'options':[str(old_options).encode()]}]
                return [Partition({'msDS-SDReferenceDomain':[b'present']} if reference_present else {})]
            def modify(self,message):changes.append(message)
        class LoadParm:
            def load_default(self):pass
            def get(self,key):return 'EXAMPLE.TEST'
        ldb=types.ModuleType('ldb');ldb.SCOPE_BASE=0;ldb.SCOPE_ONELEVEL=1;ldb.FLAG_MOD_REPLACE=2;ldb.FLAG_MOD_ADD=1;ldb.Message=Message;ldb.MessageElement=Element;ldb.Dn=lambda _,value:Dn(value)
        samba=types.ModuleType('samba');auth=types.ModuleType('samba.auth');auth.system_session=lambda:None
        param=types.ModuleType('samba.param');param.LoadParm=LoadParm
        samdb=types.ModuleType('samba.samdb');samdb.SamDB=Database
        spec=importlib.util.spec_from_file_location('test_directory',Path(__file__).resolve().parents[1]/'samba-ad-dc/directory_config.py')
        module=importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules,{'ldb':ldb,'samba':samba,'samba.auth':auth,'samba.param':param,'samba.samdb':samdb}):
            spec.loader.exec_module(module)
            result=module.configure(gc=gc)
        return result,changes
    def test_gc_bit_is_enabled_without_destroying_other_ntds_options(self):
        result,changes=self.run_directory(4)
        self.assertEqual(result['options'],5)
        self.assertEqual(changes[0]['options'].value,'5')
        self.assertEqual(changes[1]['msDS-SDReferenceDomain'].value,'DC=example,DC=test')
    def test_gc_bit_can_be_disabled_preserving_other_bits_and_existing_dns_reference(self):
        result,changes=self.run_directory(37,gc=False,reference_present=True)
        self.assertEqual(result['options'],36);self.assertEqual(len(changes),1)
    def test_existing_gc_and_dns_reference_are_idempotent(self):
        result,changes=self.run_directory(37,reference_present=True)
        self.assertTrue(result['global_catalog_enabled']);self.assertEqual(changes,[])
