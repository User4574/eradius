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
                    aaa_steps = [
                                  #mfa{
                                     module = er_aaa,
                                     function = local_password,
                                     args = [<<"arctangent">>]
                                    },
                                  #mfa{
                                     module = er_test,
                                     function = test_response,
                                     args = []
                                    }
                                 ]
                   },
                 #user{
                    name = <<"mopsy">>,
                    aaa_steps = [
                                  #mfa{
                                     module = er_aaa,
                                     function = local_challenge,
                                     args = [<<"32769430">>, <<"99101462">>]
                                    },
                                  #mfa{
                                     module = er_test,
                                     function = test_response,
                                     args = []
                                    }
                                 ]
                   }
                ]).
