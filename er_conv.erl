-module(er_conv).

-export([accept/3, reject/3, challenge/4]).

-include("eradius.hrl").

accept(Identifier, Secret, Request_Auth) ->
  Response_Attributes = [
                         #tlv{
                            type   = ?service_type,
                            length = 6,
                            value  = ?login
                           },
                         #tlv{
                            type   = ?login_service,
                            length = 6,
                            value  = ?telnet
                           },
                         #tlv{
                            type   = ?login_ip_host,
                            length = 6,
                            value  = <<192,168,1,3>>
                           }
                        ],
  Fledgling_Packet = #packet{
     code       = ?access_accept,
     identifier = Identifier,
     attributes = Response_Attributes
    },
  Length = er_packet:packet_length(Fledgling_Packet),
  Response_Auth = er_crypto:response_auth(
                    ?access_accept,
                    Identifier,
                    Length,
                    Request_Auth,
                    Response_Attributes,
                    Secret),
  Fledgling_Packet#packet{
    length        = Length,
    authenticator = Response_Auth
   }.

reject(Identifier, Secret, Request_Auth) ->
  Fledgling_Packet = #packet{
     code       = ?access_reject,
     identifier = Identifier,
     attributes = []
    },
  Length = er_packet:packet_length(Fledgling_Packet),
  Response_Auth = er_crypto:response_auth(
                    ?access_reject,
                    Identifier,
                    Length,
                    Request_Auth,
                    [],
                    Secret),
  Fledgling_Packet#packet{
    length        = Length,
    authenticator = Response_Auth
   }.

challenge(Identifier, Secret, Request_Auth, Challenge) ->
  Response_Attributes = [
                         #tlv{
                            type   = ?reply_message,
                            length = 48,
                            value  = <<"Challenge ", Challenge/binary, ".  Enter response at prompt.">>
                           },
                         #tlv{
                            type   = ?state,
                            length = byte_size(Challenge) + 2,
                            value  = Challenge
                           }
                        ],
  Fledgling_Packet = #packet{
     code       = ?access_challenge,
     identifier = Identifier,
     attributes = Response_Attributes
    },
  Length = er_packet:packet_length(Fledgling_Packet),
  Response_Auth = er_crypto:response_auth(
                    ?access_challenge,
                    Identifier,
                    Length,
                    Request_Auth,
                    Response_Attributes,
                    Secret),
  Fledgling_Packet#packet{
    length        = Length,
    authenticator = Response_Auth
   }.
