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
                    authenticate = #mfa{
                                      module = er_aaa,
                                      function = local_password,
                                      args = [<<"arctangent">>]
                                     },
                    authorise = #mfa{
                                   module = er_aaa,
                                   function = ok,
                                   args = []
                                  }
                   },
                 #user{
                    name = <<"mopsy">>,
                    authenticate = #mfa{
                                      module = er_aaa,
                                      function = local_challenge,
                                      args = [<<"32769430">>, <<"99101462">>]
                                     },
                    authorise = #mfa{
                                   module = er_aaa,
                                   function = ok,
                                   args = []
                                  }
                   }
                ]).
