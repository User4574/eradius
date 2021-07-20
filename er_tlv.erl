-module(er_tlv).

-export([parse_tlvs/1, deparse_tlvs/1, get_attr/2]).
-export([tlvs_to_facts/1, response_facts_to_tlvs/1, cook_facts/3, get_fact/3]).

-include("eradius.hrl").

parse_tlvs(Binary) ->
  parse_tlvs(Binary, []).
parse_tlvs(<<>>, Acc) ->
  Acc;
parse_tlvs(<<Type:8, Length:8, Value:(Length-2)/binary, Rest/binary>>, Acc) ->
  parse_tlvs(Rest,
             [
              #tlv{
                 type   = Type,
                 length = Length,
                 value  = Value
                }
              | Acc
             ]
            ).

deparse_tlvs(List) ->
  deparse_tlvs(List, <<>>).
deparse_tlvs([], Acc) ->
  Acc;
deparse_tlvs([#tlv{type = Type, length = Length, value = Value} | Rest], Acc) ->
  deparse_tlvs(Rest, <<Acc/binary, Type:8, Length:8, Value:(Length-2)/binary>>).

get_attr(Type, Attrs) ->
  case lists:search(fun(TLV) ->
                        #tlv{type = T} = TLV,
                        T == Type
                    end, Attrs) of
    {value, #tlv{value = V}} -> 
      V;
    false ->
      false
  end.

tlvs_to_facts(TLVs) ->
  tlvs_to_facts(TLVs, []).
tlvs_to_facts([], Facts) ->
  Facts;
tlvs_to_facts([#tlv{type=Type, value=Value} | Rest], Facts) ->
  tlvs_to_facts(Rest, [#fact{
                          namespace = tlv,
                          key = Type,
                          value = Value
                         } | Facts]).

response_facts_to_tlvs(Facts) ->
  response_facts_to_tlvs(Facts, []).
response_facts_to_tlvs([], TLVs) ->
  TLVs;
response_facts_to_tlvs([#fact{namespace = response_tlv, key = Key, value = Value} | Rest], TLVs) ->
  response_facts_to_tlvs(Rest,
                [#tlv{type = Key,
                      length = 1 +          %type
                               1 +          %length
                               size(Value), %value
                      value = Value} | TLVs]);
response_facts_to_tlvs([_ | Rest], TLVs) ->
  response_facts_to_tlvs(Rest, TLVs).

cook_facts(Secret, Request_Auth, Facts) ->
  cook_facts(Secret, Request_Auth, Facts, []).
cook_facts(_, _, [], Cooked_Facts) ->
  Cooked_Facts;
cook_facts(Secret, Request_Auth, [#fact{
                                     namespace = tlv,
                                     key = ?user_password,
                                     value = PasswordCT
                                    } | Raw_Facts], Cooked_Facts) ->
  cook_facts(Secret, Request_Auth, Raw_Facts, [#fact{
                                                  namespace = tlv,
                                                  key = ?user_password,
                                                  value = er_crypto:decrypt_password(
                                                            PasswordCT,
                                                            Secret,
                                                            Request_Auth
                                                           )} | Cooked_Facts]);
cook_facts(Secret, Request_Auth, [Raw_Fact | Raw_Facts], Cooked_Facts) ->
  cook_facts(Secret, Request_Auth, Raw_Facts, [Raw_Fact | Cooked_Facts]).

get_fact(_, _, []) ->
  false;
get_fact(Namespace, Key, [#fact{
                             namespace = Namespace,
                             key = Key,
                             value = Value
                            } | _]) ->
  Value;
get_fact(Namespace, Key, [_ | Facts]) ->
  get_fact(Namespace, Key, Facts).
