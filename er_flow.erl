-module(er_flow).

-export([get_flow/1]).

-include("eradius.hrl").
-include("config.hrl").

get_flow(Request_Facts) ->
  test_flows(?flowdb, Request_Facts).

test_flows([], _) ->
  false;

test_flows([Flow = #flow{filter = Filters} | Flows], Request_Facts) ->
  case test_filters(Filters, Request_Facts) of
    true ->
      Flow;
    false ->
      test_flows(Flows, Request_Facts)
  end.

test_filters([], _) ->
  true;

test_filters([Filter | Filters], Request_Facts) ->
  case Filter of
    #filter_fact_exact{
       namespace = Namespace,
       key = Key,
       value = Test_Value
      } ->
      Found_Value = er_tlv:get_fact(Namespace, Key, Request_Facts),
      case Found_Value of
        Test_Value ->
          test_filters(Filters, Request_Facts);
        _ ->
          false
      end
  end.
