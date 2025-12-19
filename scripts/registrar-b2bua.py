import sys
import KSR as KSR
import re

# In-memory database for user redial lists and service status
user_redial_lists = {}
user_service_status = {}  

# Service monitoring KPIs
service_stats = {  
    'total_activations': 0,
    'currently_active_users': 0,
    'max_redial_list_size': 0
}

# Mandatory function - module initiation
def mod_init():
    KSR.info("===== from Python mod init\n")
    return kamailio()

class kamailio:
    def __init__(self):
        KSR.info('===== kamailio.__init__\n')

    def child_init(self, rank):
        KSR.info('===== kamailio.child_init(%d)\n' % rank)
        return 0

    def is_acme_user(self, uri):
        if not uri: return False
        return "acme.operator" in uri

    def extract_username(self, uri):
        if not uri: return None
        match = re.match(r'sip:([^@]+)@', uri)
        if match: return match.group(1)
        return None

    def ksr_request_route(self, msg):
        if (msg.Method == "REGISTER"):
            from_uri = KSR.pv.get("$fu")
            if not self.is_acme_user(from_uri):
                KSR.sl.send_reply(403, "Forbidden - Not an ACME user")
                return 1
            KSR.info("REGISTER R-URI: " + KSR.pv.get("$ru") + "\n")
            username = self.extract_username(from_uri)
            if username:
                if username not in user_redial_lists:
                    user_redial_lists[username] = []
                    user_service_status[username] = False  # <-- Initialize service status
                    KSR.info(f"Initialized redial service for user {username}\n")
            KSR.registrar.save('location', 0)
            return 1

        # Handle MESSAGE requests for service management
        if msg.Method == "MESSAGE":  
            from_uri = KSR.pv.get("$fu")
            to_uri = KSR.pv.get("$tu")
            
            if not self.is_acme_user(from_uri):
                KSR.sl.send_reply(403, "Forbidden - Not an ACME user")
                return 1
                
            # Check if message is sent to redial@acme.operador
            if "redial@acme.operator" in to_uri:
                content = KSR.pv.get("$rb")  # Get message body
                username = self.extract_username(from_uri)
                
                if not username:
                    KSR.sl.send_reply(400, "Bad Request - Invalid user")
                    return 1
                
                # Process ACTIVATE command
                if content.startswith("ACTIVATE"):
                    parts = content.split()
                    if len(parts) < 2:
                        KSR.sl.send_reply(400, "Bad Request - Missing destinations")
                        return 1
                    
                    # Extract destinations from message
                    destinations = parts[1:]
                    user_redial_lists[username] = destinations
                    user_service_status[username] = True
                    
                    # Update service statistics
                    service_stats['total_activations'] += 1
                    service_stats['currently_active_users'] += 1
                    list_size = len(destinations)
                    if list_size > service_stats['max_redial_list_size']:
                        service_stats['max_redial_list_size'] = list_size
                    
                    KSR.info(f"Redial service activated for user {username} with destinations: {destinations}\n")
                    KSR.sl.send_reply(200, "OK - Redial service activated")
                    return 1
                
                # Unknown command
                else:
                    KSR.sl.send_reply(400, "Bad Request - Unknown command")
                    return 1
            
            # If not a service management message, forward normally
            KSR.tm.t_relay()
            return 1

        # Working as a Redirect server
        if (msg.Method == "INVITE"):                      
            KSR.info("INVITE R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.info("        From: " + KSR.pv.get("$fu") +
                              " To: " + KSR.pv.get("$tu") +"\n")
            
            if (KSR.pv.get("$tu") == "sip:nobody@acme.operator"):       
                KSR.pv.sets("$ru", "sip:nobody@sipnet.alice:9999") 
                KSR.tm.t_relay()   
                return 1                

            if (KSR.pv.get("$td") != "acme.operator"):       
                KSR.tm.t_relay()   
                KSR.rr.record_route()  
                return 1

            if (KSR.pv.get("$td") == "acme.operator"):             
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

        KSR.sl.send_reply(403, "Forbiden method")
        return 1

    def ksr_reply_route(self, msg):
        KSR.info("===== reply_route - from kamailio python script: ")
        KSR.info("  Status is:"+ str(KSR.pv.get("$rs")) + "\n")
        return 1

    def ksr_onsend_route(self, msg):
        KSR.info("===== onsend route - from kamailio python script:")
        KSR.info("   %s\n" %(msg.Type))
        return 1
