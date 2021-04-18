-module(er_auth).

-export([response_auth/6, decrypt_password/4]).

-import(er_tlv, [deparse_tlvs/2]).

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