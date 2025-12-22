import sys
import KSR as KSR
import re
import json

# =================================================================
# CONFIGURATION
# =================================================================
CONFIG = {
    "SERVICE_DOMAIN": "acme.operator",
    "SERVICE_MANAGEMENT_URI": "redial@acme.operator",
    "PIN_VALIDATION_URI": "validar@acme.pt",
    "MAX_REDIAL_ATTEMPTS": 3,
    "H_TABLE_NAME": "redial"
}
# =================================================================

# Service monitoring KPIs (stored in htable)
SERVICE_STATS_KEYS = ['total_activations', 'currently_active_users', 'max_redial_list_size']

def mod_init():
    KSR.info("===== Redial 2.0 Service - Python mod init (using htable)\n")
    for key in SERVICE_STATS_KEYS:
        if KSR.htable.sht_is_null(CONFIG["H_TABLE_NAME"], key) == -1:
            KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], key, "0")
            KSR.info(f"Initialized service stat: {key}\n")
    return kamailio()

class kamailio:
    def __init__(self):
        KSR.info('===== kamailio.__init__\n')

    def child_init(self, rank):
        KSR.info(f'===== kamailio.child_init({rank})\n')
        return 0

    # --- Helper Functions using htable ---
    def is_acme_user(self, uri):
        """Checks if the URI belongs to the configured service domain."""
        if not uri:
            KSR.err("[HELPER] is_acme_user called with a null URI.\n")
            return False
        return CONFIG["SERVICE_DOMAIN"] in uri  

    def get_user_id(self, uri):
        """Extracts a unique user ID (user@domain) from a SIP URI."""
        if not uri:
            KSR.err("[HELPER] get_user_id called with a null URI.\n")
            return None
        if not uri.startswith("sip:"):
            uri = "sip:" + uri
        # Remove 'sip:' prefix to get user@domain
        return uri[4:]

    def extract_username(self, uri):
        """Extracts the username from a SIP URI."""
        if not uri:
            KSR.err("[HELPER] extract_username called with a null URI.\n")
            return None
        if not uri.startswith("sip:"):
            uri = "sip:" + uri
        match = re.match(r'sip:([^@]+)@', uri)
        if match:
            return match.group(1)
        KSR.warn(f"[HELPER] Could not extract username from URI: {uri}\n")
        return None
    
    def extract_full_uri(self, uri_or_username):
        """Extracts the full URI from a username or URI."""
        if not uri_or_username:
            return None
        if "@" in uri_or_username:
            return uri_or_username if uri_or_username.startswith("sip:") else f"sip:{uri_or_username}"
        # Default to service domain if only a username is provided
        return f"sip:{uri_or_username}@{CONFIG['SERVICE_DOMAIN']}"

    def is_user_registered(self, user_id):
        """Checks if a user is registered using an htable flag."""
        if not user_id: 
            KSR.err("[HELPER] is_user_registered called with null user_id\n")
            return False
        key = "registered_" + user_id
        is_registered = KSR.htable.sht_get(CONFIG["H_TABLE_NAME"], key) == "1"
        KSR.dbg(f"[HELPER] Checking registration for {user_id}: {'Found' if is_registered else 'Not found'}\n")
        return is_registered

    def get_user_redial_list(self, user_id):
        """Gets user's redial list from htable."""
        key = "redial_list_" + user_id
        value = KSR.htable.sht_get(CONFIG["H_TABLE_NAME"], key)
        if value:
            destinations = value.split(',')
            KSR.dbg(f"[HELPER] Retrieved redial list for {user_id}: {destinations}\n")
            return destinations
        KSR.dbg(f"[HELPER] No redial list found for {user_id} or list is empty.\n")
        return []

    def set_user_redial_list(self, user_id, destinations):
        """Sets user's redial list in htable and updates max size stat."""
        key = "redial_list_" + user_id
        value = ','.join(destinations)
        KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], key, value)
        KSR.info(f"[HELPER] Set redial list for {user_id} to: {destinations}\n")
        
        list_size = len(destinations)
        current_max = int(KSR.htable.sht_get(CONFIG["H_TABLE_NAME"], "max_redial_list_size") or "0")
        if list_size > current_max:
            KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], "max_redial_list_size", str(list_size))
            KSR.info(f"[HELPER] Updated max redial list size to: {list_size}\n")

    def get_user_service_status(self, user_id):
        """Gets user's service status from htable."""
        key = "service_status_" + user_id
        status = KSR.htable.sht_get(CONFIG["H_TABLE_NAME"], key)
        is_active = status == "1" or (status and status.lower() == "true")
        KSR.dbg(f"[HELPER] Service status for {user_id} is: {'Active' if is_active else 'Inactive'}\n")
        return is_active

    def set_user_service_status(self, user_id, status):
        """Sets user's service status in htable and updates active users count."""
        key = "service_status_" + user_id
        was_active = self.get_user_service_status(user_id)
        KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], key, "1" if status else "0")
        KSR.info(f"[HELPER] Set service status for {user_id} to: {'Active' if status else 'Inactive'}\n")
        
        current_count = int(KSR.htable.sht_get(CONFIG["H_TABLE_NAME"], "currently_active_users") or "0")
        if status and not was_active:
            new_count = current_count + 1
            KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], "currently_active_users", str(new_count))
            KSR.info(f"[HELPER] Incremented active user count to: {new_count}\n")
        elif not status and was_active:
            new_count = max(0, current_count - 1)
            KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], "currently_active_users", str(new_count))
            KSR.info(f"[HELPER] Decremented active user count to: {new_count}\n")

    # --- Main SIP Request Routing ---
    def ksr_request_route(self, msg):
        method = msg.Method
        from_uri = KSR.pv.get("$fu")
        to_uri = KSR.pv.get("$tu")
        call_id = KSR.pv.get("$ci")
        
        KSR.info(f"[ROUTE] Received {method} from {from_uri} to {to_uri} (Call-ID: {call_id})\n")

        if method == "REGISTER":
            from_user_id = self.get_user_id(from_uri)
            if not from_user_id:
                KSR.sl.send_reply(400, "Bad Request - Invalid From URI")
                return 1

            KSR.info(f"[ROUTE] User {from_user_id} attempting to register.\n")
            
            res = KSR.registrar.save("location", 0)
            
            if res < 0:
                KSR.err(f"[ROUTE] Registration for {from_uri} failed with code {res}.\n")
                return 1

            KSR.info(f"[ROUTE] Registration for {from_uri} successful.\n")
            KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], "registered_" + from_user_id, "1")
            
            if self.is_acme_user(from_uri):
                if KSR.htable.sht_is_null(CONFIG["H_TABLE_NAME"], "redial_list_" + from_user_id) == -1:
                    KSR.info(f"[ROUTE] Initializing service data for new ACME user {from_user_id}\n")
                    self.set_user_redial_list(from_user_id, [])
                    self.set_user_service_status(from_user_id, False)

            KSR.sl.send_reply(200, "OK")
            return 1

        if method == "MESSAGE":  
            if CONFIG["SERVICE_MANAGEMENT_URI"] in to_uri:
                if not self.is_acme_user(from_uri):
                    KSR.warn(f"[ROUTE] Forbidden service management attempt from non-ACME user: {from_uri}\n")
                    KSR.sl.send_reply(403, "Forbidden - Service management for ACME users only")
                    return 1
                
                content = KSR.pv.get("$rb")
                from_user_id = self.get_user_id(from_uri)
                
                if not from_user_id:
                    KSR.sl.send_reply(400, "Bad Request - Invalid user")
                    return 1
                
                if content.startswith("ACTIVATE"):
                    if not self.is_user_registered(from_user_id):
                        KSR.info(f"[ROUTE] ACTIVATE failed: User {from_user_id} is not registered.\n")
                        KSR.sl.send_reply(403, "Forbidden - User not registered")
                        return 1

                    parts = re.split(r'\s+', content.strip())
                    if len(parts) < 2:
                        KSR.sl.send_reply(400, "Bad Request - Missing destinations")
                        return 1
                    
                    destinations = parts[1:]
                    valid_destinations = []
                    for dest in destinations:
                        if re.match(r'^[a-zA-Z0-9.\-_]+@[a-zA-Z0-9.\-_]+$', dest):
                            valid_destinations.append(dest)
                        else:
                            KSR.warn(f"[ROUTE] ACTIVATE for {from_user_id}: Skipping invalid AoR format: {dest}\n")

                    if not valid_destinations:
                        KSR.sl.send_reply(400, "Bad Request - No valid destinations provided")
                        return 1

                    self.set_user_redial_list(from_user_id, valid_destinations)
                    
                    if not self.get_user_service_status(from_user_id):
                        current_total = int(KSR.htable.sht_get(CONFIG["H_TABLE_NAME"], "total_activations") or "0")
                        KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], "total_activations", str(current_total + 1))
                    
                    self.set_user_service_status(from_user_id, True)
                    
                    KSR.info(f"[ROUTE] Redial service activated for user {from_user_id} with destinations: {valid_destinations}\n")
                    KSR.sl.send_reply(200, "OK - Redial service activated")
                    return 1
                
                elif content.strip() == "DEACTIVATE":
                    if not self.is_user_registered(from_user_id):
                        KSR.info(f"[ROUTE] DEACTIVATE failed: User {from_user_id} is not registered.\n")
                        KSR.sl.send_reply(403, "Forbidden - User not registered")
                        return 1

                    self.set_user_redial_list(from_user_id, [])
                    self.set_user_service_status(from_user_id, False)
                    
                    KSR.info(f"[ROUTE] Redial service deactivated for user {from_user_id}\n")
                    KSR.sl.send_reply(200, "OK - Redial service deactivated")
                    return 1
                
                else:
                    KSR.sl.send_reply(400, "Bad Request - Unknown command")
                    return 1
            
            KSR.info(f"[ROUTE] Forwarding MESSAGE from {from_uri} to {to_uri}\n")
            KSR.tm.t_relay()
            return 1

        if method == "PUBLISH":
            KSR.sl.send_reply(200, "OK")
            return 1

        if method == "OPTIONS":
            KSR.sl.send_reply(200, "OK")
            return 1

        if method == "INVITE":                      
            from_user_id = self.get_user_id(from_uri)
            original_uri = KSR.pv.get("$ru")
            call_key = f"call_{call_id}"
            
            # ROBUST CHECK: See if we have already stored data for this call.
            # This is more reliable than checking for a specific flag.
            caller_stored = KSR.htable.sht_get(CONFIG["H_TABLE_NAME"], f"caller_{call_key}")
            if not caller_stored:
                # This is a new call, initialize all necessary data.
                KSR.info(f"[ROUTE] Initializing call data for new call {call_key}.\n")
                KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], f"redial_attempt_{call_key}", "0")
                KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], f"caller_{call_key}", from_user_id)
                KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], f"orig_uri_{call_key}", original_uri)
                KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], f"tried_dests_{call_key}", "")
            else:
                # This is a re-entry (e.g., from a failure route), data is already present.
                KSR.info(f"[ROUTE] Call data for {call_key} already exists. Continuing.\n")

            KSR.tm.t_on_failure("ksr_failure_manage_route")
            
            if KSR.registrar.lookup("location") == 1:   
                KSR.info(f"[ROUTE] Original destination found, relaying call to {KSR.pv.get('$du') or KSR.pv.get('$ru')}\n")
                KSR.rr.record_route()
                KSR.tm.t_relay()   
                return 1
            else:
                KSR.info(f"[ROUTE] Original user {original_uri} not found in location DB. Sending 404.\n")
                KSR.sl.send_reply(404, "Not Found")
                return 1

        if method in ["ACK", "BYE", "CANCEL"]:
            if method == "CANCEL":
                if KSR.tm.t_check_trans():
                    KSR.tm.t_reply(487, "Request Terminated")
                    return 1
                else:
                    KSR.info(f"[ROUTE] No matching transaction for CANCEL\n")
                    return 1
            
            KSR.rr.loose_route()    
            KSR.tm.t_relay()
            return 1

        KSR.sl.send_reply(405, "Method Not Allowed")
        return 1

    def ksr_failure_manage_route(self, msg):
        call_id = KSR.pv.get("$ci")
        call_key = f"call_{call_id}"
        
        status_code_raw = KSR.pv.get("$rs")
        status_code = str(status_code_raw) if status_code_raw is not None else ""
        
        redial_attempt = int(KSR.htable.sht_get(CONFIG["H_TABLE_NAME"], f"redial_attempt_{call_key}") or "0")
        caller_user_id = KSR.htable.sht_get(CONFIG["H_TABLE_NAME"], f"caller_{call_key}")
        original_uri = KSR.htable.sht_get(CONFIG["H_TABLE_NAME"], f"orig_uri_{call_key}")
        
        tried_dests_str = KSR.htable.sht_get(CONFIG["H_TABLE_NAME"], f"tried_dests_{call_key}") or ""
        tried_dests = tried_dests_str.split(',') if tried_dests_str else []
        
        KSR.info(f"[FAILURE] Entered failure route. Attempt {redial_attempt}. Caller: {caller_user_id}. Status: {status_code}\n")

        if redial_attempt >= CONFIG["MAX_REDIAL_ATTEMPTS"]:
            KSR.info(f"[FAILURE] Max redial attempts ({CONFIG['MAX_REDIAL_ATTEMPTS']}) reached. Terminating call.\n")
            self.cleanup_call_data(call_key)
            KSR.tm.t_reply(486, "Busy Here")
            return 1

        # This check should now always pass due to the robust logic in ksr_request_route
        if not caller_user_id or not self.get_user_service_status(caller_user_id):
            KSR.info(f"[FAILURE] Caller {caller_user_id or 'Unknown'} does not have redial service active. Terminating call.\n")
            self.cleanup_call_data(call_key)
            KSR.tm.t_reply(404, "Not Found")
            return 1
            
        redial_list = self.get_user_redial_list(caller_user_id)
        if not redial_list:
            KSR.info(f"[FAILURE] Caller {caller_user_id} has an empty redial list. Terminating call.\n")
            self.cleanup_call_data(call_key)
            KSR.tm.t_reply(404, "Not Found")
            return 1

        next_dest = None
        for dest in redial_list:
            if self.get_user_id(dest) == caller_user_id:
                KSR.info(f"[FAILURE] Skipping redial to original caller {dest} to prevent loop.\n")
                continue
            if dest == original_uri or self.extract_full_uri(dest) == original_uri:
                KSR.info(f"[FAILURE] Skipping redial to original destination {dest} (already tried).\n")
                continue
            if dest in tried_dests:
                KSR.info(f"[FAILURE] Skipping redial to {dest} (already tried).\n")
                continue
            next_dest = dest
            break
        
        if next_dest:
            tried_dests.append(next_dest)
            KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], f"tried_dests_{call_key}", ','.join(tried_dests))
            
            if self.is_acme_user(next_dest):
                dest_user_id = self.get_user_id(next_dest)
                if not self.is_user_registered(dest_user_id):
                    KSR.warn(f"[FAILURE] Internal redial destination '{next_dest}' is not registered. Skipping it.\n")
                    KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], f"redial_attempt_{call_key}", str(redial_attempt + 1))
                    KSR.tm.t_reply(404, "Redial Destination Not Found")
                    return 1
            
            KSR.info(f"[FAILURE] Trying redial destination {next_dest} for caller {caller_user_id} (Attempt {redial_attempt + 1}).\n")
            KSR.pv.sets("$ru", self.extract_full_uri(next_dest))
            KSR.htable.sht_sets(CONFIG["H_TABLE_NAME"], f"redial_attempt_{call_key}", str(redial_attempt + 1))
            KSR.tm.t_relay()
            return 1
        else:
            KSR.info(f"[FAILURE] All valid redial destinations have been attempted for caller {caller_user_id}. Terminating call.\n")
            self.cleanup_call_data(call_key)
            KSR.tm.t_reply(486, "Busy Here")
            return 1

    def cleanup_call_data(self, call_key):
        """Helper function to clean up htable entries for a completed call."""
        # CORRECTED FUNCTION NAME: sht_rm instead of sht_remove
        KSR.htable.sht_rm(CONFIG["H_TABLE_NAME"], f"redial_attempt_{call_key}")
        KSR.htable.sht_rm(CONFIG["H_TABLE_NAME"], f"caller_{call_key}")
        KSR.htable.sht_rm(CONFIG["H_TABLE_NAME"], f"orig_uri_{call_key}")
        KSR.htable.sht_rm(CONFIG["H_TABLE_NAME"], f"tried_dests_{call_key}")

    def ksr_reply_route(self, msg):
        status_code_raw = KSR.pv.get("$rs")
        status_code = str(status_code_raw) if status_code_raw is not None else ""
        
        call_id = KSR.pv.get("$ci")
        call_key = f"call_{call_id}"
        
        KSR.dbg(f"[REPLY] Reply received - Status: {status_code}\n")
        
        if status_code.startswith("2"):
            self.cleanup_call_data(call_key)
            KSR.info(f"[REPLY] Call succeeded, cleaned up redial attempt counter for {call_key}\n")
            
        return 1

    def ksr_onsend_route(self, msg):
        KSR.dbg(f"[ONSEND] Onsend route triggered for message type: {KSR.pv.get('$rm')}\n")
        return 1