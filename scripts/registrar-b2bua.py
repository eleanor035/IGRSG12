import sys
import KSR as KSR
import re

# Service monitoring KPIs (stored in htable)
SERVICE_STATS_KEYS = ['total_activations', 'currently_active_users', 'max_redial_list_size']

# Mandatory function - module initiation
def mod_init():
    KSR.info("===== Redial 2.0 Service - Python mod init (using htable)\n")
    # Initialize service stats in htable if they don't exist
    for key in SERVICE_STATS_KEYS:
        # Use sht_is_null() to check if a key exists. It returns -1 if not found.
        if KSR.htable.sht_is_null("redial", key) == -1:
            KSR.htable.sht_sets("redial", key, "0")
            KSR.info("Initialized service stat: " + key + "\n")
    # Return an instance of the kamailio class
    return kamailio()

class kamailio:
    def __init__(self):
        KSR.info('===== kamailio.__init__\n')

    def child_init(self, rank):
        KSR.info('===== kamailio.child_init(%d)\n' % rank)
        return 0

    # --- Helper Functions using htable ---

    def is_acme_user(self, uri):
        """Checks if the URI belongs to the acme.operator domain."""
        if not uri: return False
        return "acme.operator" in uri  

    def extract_username(self, uri):
        """Extracts the username from a SIP URI."""
        if not uri: return None
        # If the URI doesn't start with 'sip:', add it for the regex to work correctly
        if not uri.startswith("sip:"):
            uri = "sip:" + uri
        match = re.match(r'sip:([^@]+)@', uri)
        if match: return match.group(1)
        return None

    def is_user_registered(self, username):
        """
        Checks if a user is registered using an htable flag.
        This is more reliable than trying to access the usrloc DB directly from Python.
        """
        if not username: return False
        key = "registered_" + username
        return KSR.htable.sht_get("redial", key) == "1"

    def get_user_redial_list(self, username):
        """Gets user's redial list from htable."""
        key = "redial_list_" + username
        value = KSR.htable.sht_get("redial", key)
        if value:
            return value.split(',')
        return []

    def set_user_redial_list(self, username, destinations):
        """Sets user's redial list in htable and updates max size stat."""
        key = "redial_list_" + username
        value = ','.join(destinations)
        KSR.htable.sht_sets("redial", key, value)
        
        # Update max_redial_list_size if needed
        list_size = len(destinations)
        current_max = int(KSR.htable.sht_get("redial", "max_redial_list_size") or "0")
        if list_size > current_max:
            KSR.htable.sht_sets("redial", "max_redial_list_size", str(list_size))

    def get_user_service_status(self, username):
        """Gets user's service status from htable."""
        key = "service_status_" + username
        status = KSR.htable.sht_get("redial", key)
        # More robust comparison to handle both "1"/"0" and "true"/"false"
        return status == "1" or (status and status.lower() == "true")

    def set_user_service_status(self, username, status):
        """Sets user's service status in htable and updates active users count."""
        key = "service_status_" + username
        was_active = self.get_user_service_status(username)
        # Use "1"/"0" for consistency with initialization
        KSR.htable.sht_sets("redial", key, "1" if status else "0")
        
        # Update currently_active_users count
        current_count = int(KSR.htable.sht_get("redial", "currently_active_users") or "0")
        if status and not was_active:
            KSR.htable.sht_sets("redial", "currently_active_users", str(current_count + 1))
        elif not status and was_active:
            KSR.htable.sht_sets("redial", "currently_active_users", str(max(0, current_count - 1)))

    # --- Main SIP Request Routing ---

    def ksr_request_route(self, msg):
        # Handle REGISTER requests
        if (msg.Method == "REGISTER"):
            from_uri = KSR.pv.get("$fu")
            if not self.is_acme_user(from_uri):
                KSR.sl.send_reply(403, "Forbidden - Not an ACME user")
                return 1
            
            username = self.extract_username(from_uri)
            if username:
                KSR.info("User " + username + " attempting to register.\n")
                
                # Initialize user data in htable if not already done
                if KSR.htable.sht_is_null("redial", "redial_list_" + username) == -1:
                    self.set_user_redial_list(username, [])
                    self.set_user_service_status(username, False)
                    KSR.info("Initialized redial service data for user " + username + "\n")
            
            # Save registration to Kamailio's location DB
            res = KSR.registrar.save("location", 0)
            
            if res < 0:
                KSR.err("Registration for " + from_uri + " failed with code " + str(res) + ".\n")
                return 1

            KSR.info("Registration for " + from_uri + " successful.\n")
            # Set a flag in htable to indicate the user is registered
            KSR.htable.sht_sets("redial", "registered_" + username, "1")
            KSR.sl.send_reply(200, "OK")
            return 1

        # Handle MESSAGE requests for service management (ACTIVATE/DEACTIVATE)
        if msg.Method == "MESSAGE":  
            from_uri = KSR.pv.get("$fu")
            to_uri = KSR.pv.get("$tu")
            
            # Only allow service management messages sent by ACME users
            if not self.is_acme_user(from_uri):
                KSR.sl.send_reply(403, "Forbidden - Not an ACME user")
                return 1
                
            # Check if the message is for the redial service
            if "redial@acme.operator" in to_uri:
                content = KSR.pv.get("$rb")
                username = self.extract_username(from_uri)
                
                if not username:
                    KSR.sl.send_reply(400, "Bad Request - Invalid user")
                    return 1
                
                # Process ACTIVATE command
                if content.startswith("ACTIVATE"):
                    if not self.is_user_registered(username):
                        KSR.info("ACTIVATE failed: User " + username + " is not registered.\n")
                        KSR.sl.send_reply(403, "Forbidden - User not registered")
                        return 1

                    parts = re.split(r'\s+', content.strip())
                    if len(parts) < 2:
                        KSR.sl.send_reply(400, "Bad Request - Missing destinations")
                        return 1
                    
                    destinations = parts[1:]
                    self.set_user_redial_list(username, destinations)
                    
                    if not self.get_user_service_status(username):
                        current_total = int(KSR.htable.sht_get("redial", "total_activations") or "0")
                        KSR.htable.sht_sets("redial", "total_activations", str(current_total + 1))
                    
                    self.set_user_service_status(username, True)
                    
                    KSR.info("Redial service activated for user " + username + " with destinations: " + str(destinations) + "\n")
                    KSR.sl.send_reply(200, "OK - Redial service activated")
                    return 1
                
                # Process DEACTIVATE command
                elif content.strip() == "DEACTIVATE":
                    if not self.is_user_registered(username):
                        KSR.info("DEACTIVATE failed: User " + username + " is not registered.\n")
                        KSR.sl.send_reply(403, "Forbidden - User not registered")
                        return 1

                    self.set_user_redial_list(username, [])
                    self.set_user_service_status(username, False)
                    
                    KSR.info("Redial service deactivated for user " + username + "\n")
                    KSR.sl.send_reply(200, "OK - Redial service deactivated")
                    return 1
                
                # Unknown command
                else:
                    KSR.sl.send_reply(400, "Bad Request - Unknown command")
                    return 1
            
            # If not a service management message, forward normally
            KSR.tm.t_relay()
            return 1

        # Handle OPTIONS requests (commonly used for keep-alive and capability discovery)
        if (msg.Method == "OPTIONS"):
            KSR.sl.send_reply(200, "OK")
            return 1

        # Handle INVITE requests (calls)
        if (msg.Method == "INVITE"):                      
            from_uri = KSR.pv.get("$fu")
            from_username = self.extract_username(from_uri)
            
            # Check if the caller has the redial service active
            if from_username and self.get_user_service_status(from_username):
                KSR.info("Caller " + from_username + " has redial service active.\n")
                redial_list = self.get_user_redial_list(from_username)
                
                # Find the first available destination in the redial list
                for dest in redial_list:
                    if self.is_user_registered(dest):
                        KSR.info("Redial: Found registered user " + dest + ". Setting as primary destination.\n")
                        KSR.pv.sets("$ru", "sip:" + dest + "@acme.operator")
                        break # Stop after finding the first available

            # Set the failure route to handle sequential forking if the first attempt fails
            KSR.tm.t_on_failure("ksr_failure_manage_route")
            
            # Try to find the callee in the location database and relay the call
            if (KSR.registrar.lookup("location") == 1):   
                KSR.info("User found, relaying call to " + KSR.pv.get("$ru") + "\n")
                KSR.rr.record_route()
                KSR.tm.t_relay()   
                return 1
            else:
                # This case handles when the original or rewritten R-URI is not found
                KSR.info("User " + KSR.pv.get("$ru") + " not found.\n")
                KSR.sl.send_reply(404, "Not Found")
                return 1

        # Handle other SIP methods
        if (msg.Method == "ACK"):
            KSR.rr.loose_route()  
            KSR.registrar.lookup("location")
            KSR.tm.t_relay()
            return 1

        if (msg.Method == "BYE"):
            KSR.rr.loose_route()    
            KSR.registrar.lookup("location")
            KSR.tm.t_relay()
            return 1

        if (msg.Method == "CANCEL"):
            KSR.rr.loose_route()    
            KSR.registrar.lookup("location")
            KSR.tm.t_relay()
            return 1

        KSR.sl.send_reply(403, "Forbidden method")
        return 1

    # --- Failure Route for Redial Logic ---
    # This route is triggered by TM module for any negative reply
    def ksr_failure_manage_route(self, msg):
        # Use t_check_status to check for specific status codes
        if KSR.tm.t_check_status("486") or KSR.tm.t_check_status("480"):
            KSR.info("===== failure_manage_route: Received a busy/unavailable response\n")
            
            # FIX: Get the username of the CALLEE (the person being called)
            # The original failed destination is in the Request-URI ($ru)
            callee_username = self.extract_username(KSR.pv.get("$ru"))
            KSR.info(f"[REDIAL] Call to callee '{callee_username}' failed. Checking their redial list.\n")
            
            # Ensure the CALLEE has the redial service active
            if not callee_username or not self.get_user_service_status(callee_username):
                KSR.info(f"[REDIAL] Callee {callee_username} does not have redial service active. Exiting.\n")
                return 1
                
            # Get the CALLEE's redial list
            redial_list = self.get_user_redial_list(callee_username)
            KSR.info(f"[REDIAL] Found redial list for {callee_username}: {redial_list}\n")
            if not redial_list:
                KSR.info(f"[REDIAL] Callee {callee_username} has an empty redial list. Exiting.\n")
                return 1

            # Iterate through the redial list to find the next available destination
            for dest in redial_list:
                # We need to check if the destination in the list is just a username or a full URI
                dest_username = self.extract_username(dest) # This will now work correctly
                
                if not dest_username:
                    KSR.info(f"[REDIAL] Could not extract username from destination '{dest}'. Skipping.\n")
                    continue

                KSR.info(f"[REDIAL] Checking if destination '{dest_username}' is registered...\n")
                if self.is_user_registered(dest_username):
                    KSR.info(f"[REDIAL] Trying next destination {dest_username} for callee {callee_username}.\n")
                    # Set the new Request-URI
                    KSR.pv.sets("$ru", "sip:" + dest_username + "@acme.operator")
                    # Relay the call to the new destination. This creates a new branch for the same transaction.
                    KSR.tm.t_relay()
                    return 1 # Stop processing this failure route
                else:
                    KSR.info(f"[REDIAL] Destination '{dest_username}' is not registered. Skipping.\n")


            # If we get here, no more destinations were available in the list
            KSR.info(f"Redial: No more destinations available for callee {callee_username}.\n")
            return 1
        
        # For other status codes, we don't do anything special
        return 1
    
    def ksr_reply_route(self, msg):
        # This route is for processing replies, but the main logic is in the failure route
        # We can keep it for logging or other reply-based actions.
        KSR.info("===== reply_route - from kamailio python script: ")
        KSR.info("  Status is:" + str(KSR.pv.get("$rs")) + "\n")
        return 1

    def ksr_onsend_route(self, msg):
        KSR.info("===== onsend route - from kamailio python script:")
        KSR.info("   " + str(msg.Type) + "\n")
        return 1