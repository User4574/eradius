-module(er_tlv).

-export([parse_tlvs/2, deparse_tlvs/2, get_attr/2]).

-include("eradius.hrl").

parse_tlvs(<<>>, Acc) ->
  Acc;
parse_tlvs(<<Type:8, Length:8, Value:(Length-2)/binary, Rest/binary>>, Acc) ->
  parse_tlvs(Rest,
             [
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

get_attr(Type, Attrs) ->
  {value, V} = lists:search(fun(TLV) ->
                                #tlv{type=T} = TLV,
                                T == Type
                            end, Attrs),
  V.
