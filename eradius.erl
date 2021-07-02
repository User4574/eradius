-module(eradius).

-export([start/0, stop/0]).

-import(er_packet, [unpack/1, pack/1]).

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
  case lists:keyfind(UserName, #user.name, ?userdb) of
    false ->
      io:format("Incoming request username does not match any user in userdb.~n"),
      er_conv:reject(Identifier, Secret, Request_Auth);
    #user{mfa = #mfa{module = Module, function = Function, args = Args}} ->
      apply(Module, Function, [Identifier, Secret, Request_Auth, Request_Attributes | Args])
  end.
