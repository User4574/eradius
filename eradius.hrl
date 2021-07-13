-define(process_name, eradius).

-record(listen, {
          host,
          auth_port,
          acct_port
         }).

-record(client, {
          host,
          secret
         }).

-record(user, {
          name,
          authenticate,
          authorise
         }).

-record(mfa, {
          module,
          function,
          args
         }).

%%% RADIUS packet
-record(packet, {
          code,
          identifier,
          length,
          authenticator,
          attributes
         }).

%%% Attribute TLV
-record(tlv, {
          type,
          length,
          value
         }).

%%% Packet codes
-define(access_request, 1).
-define(access_accept, 2).
-define(access_reject, 3).
-define(access_challenge, 11).

%%% Attribute types
-define(user_name, 1).
-define(user_password, 2).
-define(nas_ip_address, 4).
-define(nas_port, 5).
-define(service_type, 6).
-define(login_ip_host, 14).
-define(login_service, 15).
-define(reply_message, 18).
-define(state, 24).
-define(message_authenticator, 80).

%%% Service types
-define(login, <<0,0,0,1>>).

%%% Login services
-define(telnet, <<0,0,0,0>>).
