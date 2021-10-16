-module(er_test).

-export([test_response/4, password_is_username/4, lgtm/4]).

-include("eradius.hrl").

test_response(_, _, _, Facts) ->
  case lists:member(#fact{namespace = eradius, key = status, value = user_authenticated}, Facts) of
    true ->
      {ok, [
            #fact{
               namespace = response_tlv,
               key = ?service_type,
               value = ?login
              },
            #fact{
               namespace = response_tlv,
               key = ?login_service,
               value = ?telnet
              },
            #fact{
               namespace = response_tlv,
               key = ?login_ip_host,
               value = <<192,168,1,3>>
              }
           ]};
    false ->
      {ok, []}
  end.

password_is_username(_, _, _, Facts) ->
  {ok, UN} = er_tlv:get_fact(tlv, ?user_name, Facts),
  {ok, PW} = er_tlv:get_fact(tlv, ?user_password, Facts),
  if
    UN =:= PW ->
      {ok, [
            #fact{
               namespace = eradius,
               key = status,
               value = user_authenticated
              }
           ]};
    true ->
      {ok, [
            #fact{
               namespace = eradius,
               key = status,
               value = invalid_password
              }
           ]}
  end.

lgtm(_, _, _, _) ->
  {ok, [
        #fact{
           namespace = eradius,
           key = status,
           value = user_authenticated
          }
       ]}.
