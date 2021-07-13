-module(er_aaa).

-export([local_password/5, local_challenge/6]).

-include("eradius.hrl").

local_password(Identifier, Secret, Request_Auth, Request_Attributes, Password) ->
  UserPasswordCT = er_tlv:get_attr(?user_password, Request_Attributes),
  UserPassword = er_crypto:decrypt_password(UserPasswordCT, Secret, Request_Auth),
  case UserPassword =:= Password of
    true ->
      {ok, er_conv:accept(Identifier, Secret, Request_Auth)};
    false ->
      {ok, er_conv:reject(Identifier, Secret, Request_Auth)}
  end.

local_challenge(Identifier, Secret, Request_Auth, Request_Attributes, Challenge, Response) ->
  case er_tlv:get_attr(?state, Request_Attributes) of
    false ->
      {ok, er_conv:challenge(Identifier, Secret, Request_Auth, Challenge)};
    Challenge ->
      UserPasswordCT = er_tlv:get_attr(?user_password, Request_Attributes),
      UserPassword = er_crypto:decrypt_password(UserPasswordCT, Secret, Request_Auth),
      case UserPassword =:= Response of
        true ->
          {ok, er_conv:accept(Identifier, Secret, Request_Auth)};
        false ->
          {ok, er_conv:reject(Identifier, Secret, Request_Auth)}
      end
  end.
