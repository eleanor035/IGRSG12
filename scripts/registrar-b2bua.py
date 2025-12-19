import sys
import KSR as KSR
import re

# In-memory database for user redial lists and service status
user_redial_lists = {}
user_service_status = {}  

# Dictionary to track registered users
registered_users = {}

# Service monitoring KPIs
service_stats = {  
    'total_activations': 0,
    'currently_active_users': 0,
    'max_redial_list_size': 0
}

# PIN verification (simplified - all users have PIN 0000)
user_pins = {}  # In a real implementation, this would be in a database

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

    # FIXED: Use the correct domain name everywhere
    def is_acme_user(self, uri):
        if not uri: return False
        return "acme.operador" in uri  

    def extract_username(self, uri):
        if not uri: return None
        match = re.match(r'sip:([^@]+)@', uri)
        if match: return match.group(1)
        return None
    
    def initialize_user_profile(self, username):
        """Initialize user profile with automatically active redial service"""
        if username not in user_redial_lists:
            user_redial_lists[username] = {
                "user": username,
                "status": "active",  # Automatically active on registration
                "redial_list": []    # Empty list initially
            }
            # Update statistics for new user
            KSR.info(f"=== User {username} registered with automatic active redial service\n")

    def ksr_request_route(self, msg):
        if (msg.Method == "REGISTER"):
            from_uri = KSR.pv.get("$fu")
            if not self.is_acme_user(from_uri):
                KSR.sl.send_reply(403, "Forbidden - Not an ACME user")
                return 1
            
            username = self.extract_username(from_uri)
            if username:
                # Add user to the registered_users list upon successful registration
                registered_users[username] = True
                KSR.info(f"User {username} registered successfully.\n")
                
                if username not in user_redial_lists:
                    user_redial_lists[username] = []
                    user_service_status[username] = False  # Initialize service status
                    user_pins[username] = "0000"  # Initialize PIN
                    KSR.info(f"Initialized redial service for user {username}\n")
            
            # This saves the registration to Kamailio's location DB
            KSR.registrar.save('location', 0)
            # This sends a 200 OK back to the client
            KSR.sl.send_reply(200, "OK")
            return 1

        # Handle MESSAGE requests for service management
        if msg.Method == "MESSAGE":  
            from_uri = KSR.pv.get("$fu")
            to_uri = KSR.pv.get("$tu")
            
            if not self.is_acme_user(from_uri):
                KSR.sl.send_reply(403, "Forbidden - Not an ACME user")
                return 1
                
            # Check if the message is sent to redial@acme.operador
            if "redial@acme.operador" in to_uri:
                content = KSR.pv.get("$rb")  # Get message body
                username = self.extract_username(from_uri)
                
                if not username:
                    KSR.sl.send_reply(400, "Bad Request - Invalid user")
                    return 1
                
                # Process ACTIVATE command
                if content.startswith("ACTIVATE"):
                    # Check if the user is registered before allowing activation
                    if username not in registered_users:
                        KSR.info(f"ACTIVATE failed: User {username} is not registered.\n")
                        KSR.sl.send_reply(403, "Forbidden - User not registered")
                        return 1

                    parts = content.split()
                    if len(parts) < 2:
                        KSR.sl.send_reply(400, "Bad Request - Missing destinations")
                        return 1
                    
                    # Extract destinations from the message
                    destinations = parts[1:]
                    user_redial_lists[username] = destinations
                    user_service_status[username] = True
                    
                    # Update service statistics
                    service_stats['total_activations'] += 1
                    if user_service_status.get(username, False) == False:
                        service_stats['currently_active_users'] += 1
                    list_size = len(destinations)
                    if list_size > service_stats['max_redial_list_size']:
                        service_stats['max_redial_list_size'] = list_size
                    
                    KSR.info(f"Redial service activated for user {username} with destinations: {destinations}\n")
                    KSR.sl.send_reply(200, "OK - Redial service activated")
                    return 1
                
                # Process PIN verification (simplified)
                elif content.strip() == "VERIFY_PIN":
                    pin = user_pins.get(username, "0000")
                    KSR.info(f"PIN verification for user {username}: {pin}\n")
                    KSR.sl.send_reply(200, f"OK - Your PIN is: {pin}")
                    return 1
                
                # DEACTIVATE command has been removed as requested
                
                # Unknown command
                else:
                    KSR.sl.send_reply(400, "Bad Request - Unknown command")
                    return 1
            
            # If not a service management message, forward normally
            KSR.tm.t_relay()
            return 1

        # Working as a Redirect server with Redial functionality
        if (msg.Method == "INVITE"):                      
            KSR.info("INVITE R-URI: " + KSR.pv.get("$ru") + "\n")
            KSR.info("        From: " + KSR.pv.get("$fu") +
                              " To: " + KSR.pv.get("$tu") +"\n")
            
            # Get the caller and callee
            from_uri = KSR.pv.get("$fu")
            to_uri = KSR.pv.get("$ru")
            from_username = self.extract_username(from_uri)
            to_username = self.extract_username(to_uri)
            
            # Check if this is a redial scenario
            if (from_username and to_username and 
                user_service_status.get(from_username, False) and 
                to_username in user_redial_lists.get(from_username, [])):
                
                KSR.info(f"Redial scenario detected: {from_username} calling {to_username}\n")
                
                # Try to find the user in the location database
                if (KSR.registrar.lookup("location") == 1):   
                    KSR.info(f"User {to_username} found, relaying call\n")
                    KSR.tm.t_relay()   
                    KSR.rr.record_route()  
                    return 1
                else:
                    KSR.info(f"User {to_username} not found or busy, triggering redial\n")
                    # In a full implementation, this would trigger automatic redial
                    # For now, we just send a 404 response
                    KSR.sl.send_reply(404, "Not found - Redial would be triggered here")
                    return 1
            
            # Normal call processing (from the original script)
            if (KSR.pv.get("$tu") == "sip:nobody@acme.operador"):       
                KSR.pv.sets("$ru", "sip:nobody@sipnet.alice:9999") 
                KSR.tm.t_relay()   
                return 1                

            if (KSR.pv.get("$td") != "acme.operador"):       
                KSR.tm.t_relay()   
                KSR.rr.record_route()  
                return 1

            if (KSR.pv.get("$td") == "acme.operador"):             
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

        KSR.sl.send_reply(403, "Forbidden method")
        return 1

    def ksr_reply_route(self, msg):
        KSR.info("===== reply_route - from kamailio python script: ")
        KSR.info("  Status is:"+ str(KSR.pv.get("$rs")) + "\n")
        return 1

    def ksr_onsend_route(self, msg):
        KSR.info("===== onsend route - from kamailio python script:")
        KSR.info("   %s\n" %(msg.Type))
        return 1