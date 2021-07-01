-module(eradius).

-export([start/0, stop/0]).

-import(er_packet, [unpack/1, pack/1, packet_length/1]).
-import(er_tlv, [parse_tlvs/2, deparse_tlvs/2]).
-import(er_auth, [response_auth/6, decrypt_password/3]).

-include("eradius.hrl").
-include("config.hrl").

start() ->
  start(?process_name).

start(Name) ->
  case start_server() of
    {ok, PID} ->
      register(Name, PID),
      {ok, Name, PID};
    {error, Reason} ->
      {error, Reason}
  end.

stop() ->
  stop(?process_name).

stop(PIDy) ->
  PIDy ! stop.

start_server() ->
  case gen_udp:open(?listening_port, [{active, true}, binary]) of
    {ok, Socket} ->
      PID = spawn(fun() -> despatcher(Socket) end),
      gen_udp:controlling_process(Socket, PID),
      {ok, PID};
    {error, Reason} ->
      {error, socket, Reason}
  end.

despatcher(Socket) ->
  receive
    stop ->
      gen_udp:close(Socket);
    {udp, Sock, IP, Port, Data} ->
      spawn(fun() -> handler(Sock, IP, Port, Data) end),
      despatcher(Socket)
  end.

handler(_Socket, _IP, _Port, _Data) ->
  Request = er_packet:unpack(_Data),
  io:format("Got packet:~n~p~n", [Request]),
  SecretR = lists:keyfind(_IP, #client.host, ?secretdb),
  case SecretR of
    false ->
      io:format("Incoming request source IP does not match any client in the database.~n");
    #client{secret = Secret} ->
      Response = respond(Secret, Request),
      io:format("Returning packet:~n~p~n", [Response]),
      gen_udp:send(_Socket, _IP, _Port, er_packet:pack(Response))
  end.

respond(Secret, #packet{
                   code          = ?access_request,
                   identifier    = Identifier,
                   authenticator = Request_Auth,
                   attributes    = Request_Attributes
                  }) ->
  UserName = er_tlv:get_attr(?user_name, Request_Attributes),
  UserPasswordCT = er_tlv:get_attr(?user_password, Request_Attributes),
  UserPassword = er_auth:decrypt_password(UserPasswordCT, Secret, Request_Auth),
  State = er_tlv:get_attr(?state, Request_Attributes),
  case State of
    false ->
      case lists:search(fun(Auth_Pol) ->
                            {UN, UP, _, _} = Auth_Pol,
                            (UN =:= UserName) and (UP =:= UserPassword)
                        end, ?localdb) of
        {value, {UserName, UserPassword, false, false}} ->
          accept(Identifier, Secret, Request_Auth);
        {value, {UserName, UserPassword, Challenge, _}} ->
          challenge(Identifier, Secret, Request_Auth, Challenge);
        false ->
          reject(Identifier, Secret, Request_Auth)
      end;
    _ ->
      case lists:search(fun(Auth_Pol) ->
                            {UN, _, _, CR} = Auth_Pol,
                            (UN =:= UserName) and (CR =:= UserPassword)
                        end, ?localdb) of
        {value, {UserName, _, State, UserPassword}} ->
          accept(Identifier, Secret, Request_Auth);
        false ->
          reject(Identifier, Secret, Request_Auth)
      end
  end.

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
  Length = packet_length(Fledgling_Packet),
  Response_Auth = er_auth:response_auth(
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
  Length = packet_length(Fledgling_Packet),
  Response_Auth = er_auth:response_auth(
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
  Length = packet_length(Fledgling_Packet),
  Response_Auth = er_auth:response_auth(
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
