import sys
import KSR as KSR
import re  
# In-memory database for user redial lists and service status
# In a real implementation, this would be replaced with a proper database
user_redial_lists = {} 
# Mandatory function - module initiation
def mod_init():
    KSR.info("===== from Python mod init\n")
    return kamailio()

class kamailio:
    # Mandatory function - Kamailio class initiation
    def __init__(self):
        KSR.info('===== kamailio.__init__\n')

    # Mandatory function - Kamailio subprocesses
    def child_init(self, rank):
        KSR.info('===== kamailio.child_init(%d)\n' % rank)
        return 0

    # Helper function to check if a user belongs to acme.operador domain
    def is_acme_user(self, uri):  
        if not uri:
            return False
        return "acme.operador" in uri

    # Helper function to extract username from URI
    def extract_username(self, uri):  
        if not uri:
            return None
        # Extract username from sip:username@domain format
        match = re.match(r'sip:([^@]+)@', uri)
        if match:
            return match.group(1)
        return None

    # Function called for REQUEST messages received 
    def ksr_request_route(self, msg):
        # Working as a Registrar server
        if (msg.Method == "REGISTER"):
            from_uri = KSR.pv.get("$fu")
            
            # Check if user belongs to acme.operador domain
            if not self.is_acme_user(from_uri):  
                KSR.sl.send_reply(403, "Forbidden - Not an ACME user")
                return 1
                
            KSR.info("REGISTER R-URI: " + KSR.pv.get("$ru") + "\n")      
            KSR.info("            To: " + KSR.pv.get("$tu") +
                           " Contact: " + KSR.hdr.get("Contact") +"\n")  
            
            username = self.extract_username(from_uri)  
            if username:
                # Initialize user data if not exists
                if username not in user_redial_lists:
                    user_redial_lists[username] = []
                    KSR.info(f"Initialized redial service for user {username}\n")
            
            KSR.registrar.save('location', 0)                            
            return 1

        # Working as a Redirect server
        if (msg.Method == "INVITE"):                      
            KSR.info("INVITE R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.info("        From: " + KSR.pv.get("$fu") +
                              " To: " + KSR.pv.get("$tu") +"\n")
            
            # A special destination with the objective of failing...
            if (KSR.pv.get("$tu") == "sip:nobody@sipnet.a"):       
                KSR.pv.sets("$ru", "sip:nobody@sipnet.alice:9999") 
                
                # Definition of on_failure for INVITE
                KSR.tm.t_relay()   
                return 1                

            if (KSR.pv.get("$td") != "sipnet.a"):       
                KSR.tm.t_relay()   
                KSR.rr.record_route()  
                return 1

            if (KSR.pv.get("$td") == "sipnet.a"):             
                if (KSR.registrar.lookup("location") == 1):   
                    KSR.tm.t_relay()   
                    KSR.rr.record_route()  
                    return 1
                else:
                    KSR.sl.send_reply(404, "Not found")
                    return 1

        if (msg.Method == "ACK"):
            KSR.info("ACK R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.rr.loose_route()  
            KSR.registrar.lookup("location")
            KSR.tm.t_relay()
            return 1

        if (msg.Method == "BYE"):
            KSR.info("BYE R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.rr.loose_route()    
            KSR.registrar.lookup("location")
            KSR.tm.t_relay()
            return 1

        if (msg.Method == "CANCEL"):
            KSR.info("CANCEL R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.rr.loose_route()    
            KSR.registrar.lookup("location")
            KSR.tm.t_relay()
            return 1

        # If this part is reached then Method is not allowed
        KSR.sl.send_reply(403, "Forbiden method")
        return 1

    # Function called for REPLY messages received
    def ksr_reply_route(self, msg):
        KSR.info("===== reply_route - from kamailio python script: ")
        KSR.info("  Status is:"+ str(KSR.pv.get("$rs")) + "\n")
        return 1

    # Function called for messages sent/transit
    def ksr_onsend_route(self, msg):
        KSR.info("===== onsend route - from kamailio python script:")
        KSR.info("   %s\n" %(msg.Type))
        return 1
