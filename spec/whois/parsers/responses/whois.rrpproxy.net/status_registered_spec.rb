# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.rrpproxy.net/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.rrpproxy.net.rb'

describe Whois::Parsers::WhoisRrpproxyNet, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.rrpproxy.net/status_registered.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#domain" do
    it do
      expect(subject.domain).to eq("multisafepay.com")
    end
  end
  describe "#domain_id" do
    it do
      expect(subject.domain_id).to eq("334322677_DOMAIN_COM-VRSN")
    end
  end
  describe "#status" do
    it do
      expect(subject.status).to eq(:registered)
    end
  end
  describe "#available?" do
    it do
      expect(subject.available?).to eq(false)
    end
  end
  describe "#registered?" do
    it do
      expect(subject.registered?).to eq(true)
    end
  end
  describe "#created_on" do
    it do
      expect(subject.created_on).to be_a(Time)
      expect(subject.created_on).to eq(Time.parse("2006-02-03 19:44:56 UTC"))
    end
  end
  describe "#updated_on" do
    it do
      expect(subject.updated_on).to be_a(Time)
      expect(subject.updated_on).to eq(Time.parse("2014-02-04 08:34:14 UTC"))
    end
  end
  describe "#expires_on" do
    it do
      expect { subject.expires_on }.to raise_error(Whois::AttributeNotSupported)
    end
  end
  describe "#registrar" do
    it do
      expect(subject.registrar).to be_a(Whois::Parser::Registrar)
      expect(subject.registrar.id).to eq("269")
      expect(subject.registrar.name).to eq("Key-Systems GmbH")
      expect(subject.registrar.organization).to eq("Key-Systems GmbH")
      expect(subject.registrar.url).to eq("http://www.reasonnet.com")
    end
  end
  describe "#registrant_contacts" do
    it do
      expect(subject.registrant_contacts).to be_a(Array)
      expect(subject.registrant_contacts.size).to eq(1)
      expect(subject.registrant_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.registrant_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_REGISTRANT)
      expect(subject.registrant_contacts[0].id).to eq("P-DQJ547")
      expect(subject.registrant_contacts[0].name).to eq("David Jacobs")
      expect(subject.registrant_contacts[0].organization).to eq("ReasonNet B.V.")
      expect(subject.registrant_contacts[0].address).to eq("Gyroscoopweg 134")
      expect(subject.registrant_contacts[0].city).to eq("Amsterdam")
      expect(subject.registrant_contacts[0].zip).to eq("1042 AZ")
      expect(subject.registrant_contacts[0].state).to eq("NH")
      expect(subject.registrant_contacts[0].country).to eq(nil)
      expect(subject.registrant_contacts[0].country_code).to eq("NL")
      expect(subject.registrant_contacts[0].phone).to eq("+31.205060035")
      expect(subject.registrant_contacts[0].fax).to eq("+31.205060038")
      expect(subject.registrant_contacts[0].email).to eq("domains@reasonnet.com")
      expect(subject.registrant_contacts[0].created_on).to eq(nil)
      expect(subject.registrant_contacts[0].updated_on).to eq(nil)
    end
  end
  describe "#admin_contacts" do
    it do
      expect(subject.admin_contacts).to be_a(Array)
      expect(subject.admin_contacts.size).to eq(1)
      expect(subject.admin_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.admin_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_ADMINISTRATIVE)
      expect(subject.admin_contacts[0].id).to eq("P-OEG220")
      expect(subject.admin_contacts[0].name).to eq("Olaf Geurs")
      expect(subject.admin_contacts[0].organization).to eq("ION")
      expect(subject.admin_contacts[0].address).to eq("Vlierweg 12")
      expect(subject.admin_contacts[0].city).to eq("Amsterdam")
      expect(subject.admin_contacts[0].zip).to eq("1032 LG")
      expect(subject.admin_contacts[0].state).to eq("NH")
      expect(subject.admin_contacts[0].country).to eq(nil)
      expect(subject.admin_contacts[0].country_code).to eq("NL")
      expect(subject.admin_contacts[0].phone).to eq("+31.204949100")
      expect(subject.admin_contacts[0].fax).to eq("")
      expect(subject.admin_contacts[0].email).to eq("domains@reasonnet.com")
      expect(subject.admin_contacts[0].created_on).to eq(nil)
      expect(subject.admin_contacts[0].updated_on).to eq(nil)
    end
  end
  describe "#technical_contacts" do
    it do
      expect(subject.technical_contacts).to be_a(Array)
      expect(subject.technical_contacts.size).to eq(1)
      expect(subject.technical_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.technical_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_TECHNICAL)
      expect(subject.technical_contacts[0].id).to eq("P-OEG220")
      expect(subject.technical_contacts[0].name).to eq("Olaf Geurs")
      expect(subject.technical_contacts[0].organization).to eq("ION")
      expect(subject.technical_contacts[0].address).to eq("Vlierweg 12")
      expect(subject.technical_contacts[0].city).to eq("Amsterdam")
      expect(subject.technical_contacts[0].zip).to eq("1032 LG")
      expect(subject.technical_contacts[0].state).to eq("NH")
      expect(subject.technical_contacts[0].country).to eq(nil)
      expect(subject.technical_contacts[0].country_code).to eq("NL")
      expect(subject.technical_contacts[0].phone).to eq("+31.204949100")
      expect(subject.technical_contacts[0].fax).to eq("")
      expect(subject.technical_contacts[0].email).to eq("domains@reasonnet.com")
      expect(subject.technical_contacts[0].created_on).to eq(nil)
      expect(subject.technical_contacts[0].updated_on).to eq(nil)
    end
  end
  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers.size).to eq(2)
      expect(subject.nameservers[0]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[0].name).to eq("ns.teletik.nl")
      expect(subject.nameservers[0].ipv4).to eq(nil)
      expect(subject.nameservers[0].ipv6).to eq(nil)
      expect(subject.nameservers[1]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[1].name).to eq("ns3.teletik.nl")
      expect(subject.nameservers[1].ipv4).to eq(nil)
      expect(subject.nameservers[1].ipv6).to eq(nil)
    end
  end
end
