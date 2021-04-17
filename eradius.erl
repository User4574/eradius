-module(eradius).
-export([start/0, stop/0]).

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
  Request = unpack(_Data),
  Response = respond(Request),
  gen_udp:send(_Socket, _IP, _Port, pack(Response)).

unpack(<<
         Code:8,
         Identifier:8,
         Length:16,
         Authenticator:16/binary,
         Attributes:(Length-20)/binary
       >>) ->
  TLVs = parse_tlvs(Attributes, []),
  Packet = #packet{
              code=Code,
              identifier=Identifier,
              length=Length,
              authenticator=Authenticator,
              attributes=TLVs
             },
  io:format("Got packet:~n~p~n", [Packet]),
  Packet.

pack(#packet{
        code=Code,
        identifier=Identifier,
        length=Length,
        authenticator=Authenticator,
        attributes=Attributes
       }) ->
  Deparsed_TLVs = deparse_tlvs(Attributes, <<>>),
  <<
    Code:8,
    Identifier:8,
    Length:16,
    Authenticator:16/binary,
    Deparsed_TLVs/binary
  >>.

parse_tlvs(<<>>, Acc) ->
  Acc;
parse_tlvs(<<Type:8, Length:8, Value:(Length-2)/binary, Rest/binary>>, Acc) ->
  parse_tlvs(Rest, [
                    #tlv{
                       type=Type,
                       length=Length,
                       value=Value
                      }
                    | Acc
                   ]
            ).

deparse_tlvs([], Acc) ->
  Acc;
deparse_tlvs([#tlv{type=Type, length=Length, value=Value} | Rest], Acc) ->
  deparse_tlvs(Rest, <<Acc/binary, Type:8, Length:8, Value:(Length-2)/binary>>).

respond(#packet{
          code=?access_request,
          identifier=Identifier,
          authenticator=Request_Auth,
          attributes=Request_Attributes
         }) ->
  #tlv{value=UserName} = get_attr(?user_name, Request_Attributes),
  #tlv{value=UserPasswordCT} = get_attr(?user_password, Request_Attributes),
  UserPassword = decrypt_password(UserPasswordCT, ?secret, Request_Auth, <<>>),
  io:format("Got User-Password: ~p~n", [UserPassword]),
  case lists:member({UserName, UserPassword}, ?localdb) of
    true ->
      accept(Identifier, Request_Auth);
    _ ->
      reject(Identifier, Request_Auth)
  end.

accept(Identifier, Request_Auth) ->
  Response_Attributes = [
                         #tlv{
                            type=?service_type,
                            length=6,
                            value=?login
                           },
                         #tlv{
                            type=?login_service,
                            length=6,
                            value=?telnet
                           },
                         #tlv{
                            type=?login_ip_host,
                            length=6,
                            value = <<192,168,1,3>>
                           }
                        ],
  Fledgling_Packet = #packet{
     code=?access_accept,
     identifier=Identifier,
     attributes=Response_Attributes
    },
  Length = packet_length(Fledgling_Packet),
  Response_Auth = response_auth(
                    ?access_accept,
                    Identifier,
                    Length,
                    Request_Auth,
                    Response_Attributes,
                    ?secret),
  Packet = Fledgling_Packet#packet{
             length=Length,
             authenticator=Response_Auth
            },
  io:format("Returning packet:~n~p~n", [Packet]),
  Packet.

reject(Identifier, Request_Auth) ->
  Fledgling_Packet = #packet{
     code=?access_reject,
     identifier=Identifier,
     attributes=[]
    },
  Length = packet_length(Fledgling_Packet),
  Response_Auth = response_auth(
                    ?access_reject,
                    Identifier,
                    Length,
                    Request_Auth,
                    [],
                    ?secret),
  Packet = Fledgling_Packet#packet{
             length=Length,
             authenticator=Response_Auth
            },
  io:format("Returning packet:~n~p~n", [Packet]),
  Packet.

packet_length(#packet{attributes=Attrs}) ->
  1 + %code
  1 + %identifier
  2 + %length
  16 + %authenticator
  packet_attributes_length(Attrs).

packet_attributes_length([]) ->
  0;
packet_attributes_length([#tlv{length=L} | Rest]) ->
  L + packet_attributes_length(Rest).

response_auth(Code, Identifier, Length, Request_Auth, Response_Attributes, Secret) ->
  Deparsed_TLVs = deparse_tlvs(Response_Attributes, <<>>),
  crypto:hash(md5, <<
                     Code,
                     Identifier,
                     Length:16,
                     Request_Auth/binary,
                     Deparsed_TLVs/binary,
                     Secret/binary
                   >>
             ).

decrypt_password(<<>>, _, _, Acc) ->
  list_to_binary(
    lists:reverse(
      lists:dropwhile(
        fun
          (0) -> true;
          (_) -> false
        end,
        lists:reverse(binary_to_list(Acc))
       )
     )
   );
decrypt_password(<<C:16/binary, Rest/binary>>, Secret, Key, Acc) ->
  B = crypto:hash(md5, <<Secret/binary, Key/binary>>),
  <<Bi:16/integer-unit:8>> = B,
  <<Ci:16/integer-unit:8>> = C,
  Pi = Bi bxor Ci,
  P = <<Pi:16/integer-unit:8>>,
  decrypt_password(Rest, Secret, C, <<Acc/binary, P/binary>>).

get_attr(Type, Attrs) ->
  {value, V} = lists:search(fun(TLV) ->
                                #tlv{type=T} = TLV,
                                T == Type
                            end, Attrs),
  V.
