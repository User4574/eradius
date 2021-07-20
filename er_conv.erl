-module(er_conv).

-export([accept/4, reject/4, challenge/5]).

-include("eradius.hrl").

construct_response(Type, Identifier, Secret, Request_Auth, Response_Attributes) ->
  Fledgling_Packet = #packet{
     code       = Type,
     identifier = Identifier,
     attributes = Response_Attributes
    },
  Length = er_packet:packet_length(Fledgling_Packet),
  Response_Auth = er_crypto:response_auth(
                    Type,
                    Identifier,
                    Length,
                    Request_Auth,
                    Response_Attributes,
                    Secret),
  Fledgling_Packet#packet{
    length        = Length,
    authenticator = Response_Auth
   }.

accept(Identifier, Secret, Request_Auth, Response_Attributes) ->
  construct_response(?access_accept, Identifier, Secret, Request_Auth, Response_Attributes).

reject(Identifier, Secret, Request_Auth, Response_Attributes) ->
  construct_response(?access_reject, Identifier, Secret, Request_Auth, Response_Attributes).

challenge(Identifier, Secret, Request_Auth, Response_Attributes, Challenge) ->
  Challenge_Attributes = [#tlv{
                             type   = ?reply_message,
                             length = 48,
                             value  = <<"Challenge ", Challenge/binary, ".  Enter response at prompt.">>
                            },
                          #tlv{
                             type   = ?state,
                             length = byte_size(Challenge) + 2,
                             value  = Challenge
                            }
                          | Response_Attributes],
  construct_response(?access_challenge, Identifier, Secret, Request_Auth, Challenge_Attributes).
