#!/usr/bin/perl
use strict;
use warnings;
use JSON;

open IN, "< key";
our $apikey = <IN>;
$apikey =~ s/'//g;
chomp $apikey;
close IN;

my %scans;
my @result;

while(<STDIN>){
  chomp;
  my $json = `curl -v -F 'file=\@$_' -F apikey=$apikey https://www.virustotal.com/vtapi/v2/file/scan 2>/dev/null`;
  my $ret = decode_json($json);
  $scans{$_} = $ret->{scan_id};
  sleep 15; #4try / 1min
}

#sleep 60;

for my $key(keys %scans){
  $scans{$key} =~ s/'//g;
  my $json = `curl -v --request POST --url 'https://www.virustotal.com/vtapi/v2/file/report' -d apikey=$apikey -d 'resource=$scans{$key}' 2>/dev/null`;
  my $ret = decode_json($json);
  $ret->{path} = $key;
  push @result, $ret;
  sleep 15;
}

open OUT, "> out_".time.".csv";
print OUT "path,sha256,name ...\n";
for my $data (@result){
  print OUT "$data->{path},$data->{sha256}";
  for my $scan (keys %{$data->{scans}}){
    if($data->{scans}->{$scan}->{result}){
      print OUT ",$data->{scans}->{$scan}->{result}";
    }
  }
  print OUT "\n";
}

close OUT;
#print encode_json(\@result);
