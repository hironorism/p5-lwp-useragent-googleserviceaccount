package LWP::UserAgent::GoogleServiceAccount;
use strict;
use warnings;

use JSON;
use JSON::WebToken;
use LWP::UserAgent;
use HTML::Entities;
use Carp;

sub new {
    my ($class, %param) = @_;
    my $time = time;
    my $self = {
        account_id => $param{account_id} || "",
        scope      => $param{scope}      || [],
        expire     => $param{expire}     || $time + 3600,
        issued_at  => $param{issued_at}  || $time,
        signature  => $param{signature}  || "",
    };
    return bless $self, $class;
}

sub authorized_ua {
    my ($self) = @_;
    if (!$self->{account_id}) {
        carp "service account id must be set.";
        return;
    }
    if (!$self->{signature}) {
        carp "signature must be set.";
        return;
    }
    if (@{ $self->{scope} } == 0) {
        carp "no scope is set.";
        return;
    }

    # https://developers.google.com/accounts/docs/OAuth2ServiceAccount
    my $jwt = JSON::WebToken->encode(
        {
            # your service account id here
            iss   => $self->{account_id},
            scope => join(" ", @{$self->{scope}}),
            aud   => 'https://accounts.google.com/o/oauth2/token',
            exp   => $self->{expire},
            iat   => $self->{issued_at},
        },
        $self->{signature},
        'RS256',
        {typ => 'JWT'},
    );

    my $ua = LWP::UserAgent->new();
    my $response = $ua->post('https://accounts.google.com/o/oauth2/token',
        {
            grant_type => encode_entities('urn:ietf:params:oauth:grant-type:jwt-bearer'),
            assertion  => $jwt,
        }
    );

    # failed
    unless($response->is_success()) {
        carp($response->code."\n".$response->content."\n");
        return;
    }

    my $data = JSON::decode_json($response->content);

    # The token is added to the HTTP authentication header as a bearer
    my $api_ua = LWP::UserAgent->new();
    $api_ua->default_header(Authorization => 'Bearer ' . $data->{access_token});
    return $api_ua;
}
1;
