-module(er_aaa).

-export([local_password/5, local_challenge/6]).

-include("eradius.hrl").

local_password(_Identifier, _Secret, _Request_Auth, _Request_Facts, Password) ->
  case er_tlv:get_fact(tlv, ?user_password, _Request_Facts) of
    {ok, UserPassword} ->
      case UserPassword =:= Password of
        true ->
          {ok, [#fact{
                   namespace = eradius,
                   key = status,
                   value = user_authenticated
                  }]};
        false ->
          {ok, [#fact{
                   namespace = eradius,
                   key = status,
                   value = invalid_password
                  }]}
      end;
    _ ->
      {error, "Password not received."}
  end.

local_challenge(_Identifier, _Secret, _Request_Auth, _Request_Facts, Challenge, _Response) ->
  case er_tlv:get_fact(tlv, ?state, _Request_Facts) of
    {error, key_not_found} ->
      {ok, [#fact{
               namespace = eradius,
               key = status,
               value = issue_challenge
              },
            #fact{
               namespace = eradius,
               key = challenge,
               value = Challenge
              }]};
    {ok, Challenge} ->
      case er_tlv:get_fact(tlv, ?user_password, _Request_Facts) of
        {ok, UserPassword} ->
          case UserPassword =:= _Response of
            true ->
              {ok, [#fact{
                       namespace = eradius,
                       key = status,
                       value = user_authenticated
                      }]};
            false ->
              {ok, [#fact{
                       namespace = eradius,
                       key = status,
                       value = bad_response
                      }]}
          end;
        _ ->
          {error, "Password not received."}
      end
  end.
