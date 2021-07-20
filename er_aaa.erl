-module(er_aaa).

-export([local_password/5, local_challenge/6]).

-include("eradius.hrl").

local_password(_Identifier, _Secret, _Request_Auth, _Request_Facts, Password) ->
  UserPassword = er_tlv:get_fact(tlv, ?user_password, _Request_Facts),
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
  end.

local_challenge(_Identifier, _Secret, _Request_Auth, _Request_Facts, Challenge, _Response) ->
  case er_tlv:get_fact(tlv, ?state, _Request_Facts) of
    false ->
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
    Challenge ->
      UserPassword = er_tlv:get_fact(tlv, ?user_password, _Request_Facts),
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
      end
  end.
