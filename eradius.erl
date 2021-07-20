-module(eradius).

-export([start/0, stop/0]).

-include("eradius.hrl").
-include("config.hrl").

start() ->
  start(?process_name).

start(Name) ->
  case start_server(?listener) of
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

start_server(#listen{host = Host, auth_port = AuthPort}) ->
  case gen_udp:open(AuthPort, [{ip, Host}, {active, true}, binary]) of
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
      case respond(Secret, Request) of
        {ok, Response} ->
          io:format("Returning packet:~n~p~n", [Response]),
          gen_udp:send(_Socket, _IP, _Port, er_packet:pack(Response));
        {error, Reason} ->
          io:format("Error, not responding:~n~p~n", [Reason])
      end
  end.

respond(Secret, #packet{
                   code          = ?access_request,
                   identifier    = Identifier,
                   authenticator = Request_Auth,
                   attributes    = Request_Attributes
                  }) ->
  Request_Facts = er_tlv:cook_facts(Secret, Request_Auth, er_tlv:tlvs_to_facts(Request_Attributes)),
  UserName = er_tlv:get_fact(tlv, ?user_name, Request_Facts),
  case lists:keyfind(UserName, #user.name, ?userdb) of
    false ->
      io:format("Incoming request username does not match any user in userdb.~n"),
      {ok, er_conv:reject(Identifier, Secret, Request_Auth)};
    #user{ aaa_steps = AAA_Steps } ->
      Computed_Facts = chain_aaa_steps(Identifier, Secret, Request_Auth, AAA_Steps, Request_Facts),
      make_decision(Identifier, Secret, Request_Auth, Computed_Facts)
  end.

chain_aaa_steps(_, _, _, [], Facts) ->
  Facts;
chain_aaa_steps(Identifier, Secret, Request_Auth, [#mfa{module = Mod, function = Fun, args = Args} | More_Steps], Facts) ->
  case apply(Mod, Fun, [Identifier, Secret, Request_Auth, Facts | Args]) of
    {ok, New_Facts} ->
      chain_aaa_steps(Identifier, Secret, Request_Auth, More_Steps, Facts ++ New_Facts);
    {error, Reason} ->
      {error, Reason}
  end.

make_decision(Identifier, Secret, Request_Auth, Facts) ->
  Response_Attributes = er_tlv:response_facts_to_tlvs(Facts),
  case lists:member(#fact{namespace = eradius, key = status, value = user_authenticated}, Facts) of
    true ->
      {ok, er_conv:accept(Identifier, Secret, Request_Auth, Response_Attributes)};
    false ->
      case lists:member(#fact{namespace = eradius, key = status, value = invalid_password}, Facts) of
        true ->
          {ok, er_conv:reject(Identifier, Secret, Request_Auth, Response_Attributes)};
        false ->
          case lists:member(#fact{namespace = eradius, key = status, value = issue_challenge}, Facts) of
            true ->
              Challenge = er_tlv:get_fact(eradius, challenge, Facts),
              {ok, er_conv:challenge(Identifier, Secret, Request_Auth, Response_Attributes, Challenge)};
            false ->
              case lists:member(#fact{namespace = eradius, key = status, value = bad_response}, Facts) of
                true ->
                  {ok, er_conv:reject(Identifier, Secret, Request_Auth, Response_Attributes)};
                false ->
                  {error, "Authentication fell through."}
              end
          end
      end
  end.
