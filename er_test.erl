-module(er_test).

-export([test_response/4]).

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
