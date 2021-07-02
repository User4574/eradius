-define(listener, #listen{
                     host = {127, 0, 0, 1},
                     auth_port = 1812,
                     acct_port = 1813
                    }).

-define(secretdb, [
                   #client{
                      host = {127, 0, 0, 1},
                      secret = <<"xyzzy5461">>
                     }
                  ]).

-define(userdb, [
                 #user{
                    name = <<"nemo">>,
                    mfa = #mfa{
                             module = er_auth,
                             function = with_local_password,
                             args = [<<"arctangent">>]
                            }
                   },
                 #user{
                    name = <<"mopsy">>,
                    mfa = #mfa{
                             module = er_auth,
                             function = with_local_challenge,
                             args = [<<"32769430">>, <<"99101462">>]
                            }
                   }
                ]).
