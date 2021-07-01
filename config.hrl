-define(listening_port, 1812).

-define(secretdb, [
                   #client{
                      host = {127, 0, 0, 1},
                      secret = <<"xyzzy5461">>
                     }
                  ]).

-define(localdb, [
                  {<<"nemo">>, <<"arctangent">>, false, false},
                  {<<"mopsy">>, <<"challenge">>, <<"32769430">>, <<"99101462">>}
                 ]).
