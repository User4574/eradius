-module(er_auth).

-export([response_auth/6, decrypt_password/3]).
-export([with_local_password/5, with_local_challenge/6]).

-import(er_tlv, [deparse_tlvs/2, get_attr/2]).
-import(er_conv, [accept/3, reject/3, challenge/4]).

-include("eradius.hrl").

response_auth(Code, Identifier, Length, Request_Auth, Response_Attributes, Secret) ->
  Deparsed_TLVs = er_tlv:deparse_tlvs(Response_Attributes, <<>>),
  crypto:hash(md5, <<
                     Code,
                     Identifier,
                     Length:16,
                     Request_Auth/binary,
                     Deparsed_TLVs/binary,
                     Secret/binary
                   >>
             ).

decrypt_password(CipherText, Secret, Key) ->
  decrypt_password(CipherText, Secret, Key, <<>>).
decrypt_password(<<>>, _, _, Acc) ->
  list_to_binary(
    lists:reverse(
      lists:dropwhile(
        fun (T) -> T =:= 0 end,
        lists:reverse(
          binary_to_list(Acc)
         )
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

with_local_password(Identifier, Secret, Request_Auth, Request_Attributes, Password) ->
  UserPasswordCT = er_tlv:get_attr(?user_password, Request_Attributes),
  UserPassword = decrypt_password(UserPasswordCT, Secret, Request_Auth),
  case UserPassword =:= Password of
    true ->
      {ok, er_conv:accept(Identifier, Secret, Request_Auth)};
    false ->
      {ok, er_conv:reject(Identifier, Secret, Request_Auth)}
  end.

with_local_challenge(Identifier, Secret, Request_Auth, Request_Attributes, Challenge, Response) ->
  case er_tlv:get_attr(?state, Request_Attributes) of
    false ->
      {ok, er_conv:challenge(Identifier, Secret, Request_Auth, Challenge)};
    Challenge ->
      UserPasswordCT = er_tlv:get_attr(?user_password, Request_Attributes),
      UserPassword = decrypt_password(UserPasswordCT, Secret, Request_Auth),
      case UserPassword =:= Response of
        true ->
          {ok, er_conv:accept(Identifier, Secret, Request_Auth)};
        false ->
          {ok, er_conv:reject(Identifier, Secret, Request_Auth)}
      end
  end.
