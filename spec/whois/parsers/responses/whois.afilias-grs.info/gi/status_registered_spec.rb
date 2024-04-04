# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.afilias-grs.info/gi/status_registered.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.afilias-grs.info.rb'

describe Whois::Parsers::WhoisAfiliasGrsInfo, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.afilias-grs.info/gi/status_registered.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#disclaimer" do
    it do
      expect(subject.disclaimer).to eq("Access to CCTLD WHOIS information is provided to assist persons in determining the contents of a domain name registration record in the Afilias registry database. The data in this record is provided by Afilias Limited for informational purposes only, and Afilias does not guarantee its accuracy.  This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to: (a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (b) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or Afilias except as reasonably necessary to register domain names or modify existing registrations. All rights reserved. Afilias reserves the right to modify these terms at any time. By submitting this query, you agree to abide by this policy.")
    end
  end
  describe "#domain" do
    it do
      expect(subject.domain).to eq("sapphire.gi")
    end
  end
  describe "#domain_id" do
    it do
      expect(subject.domain_id).to eq("D68296-LRCC")
    end
  end
  describe "#status" do
    it do
      expect(subject.status).to eq(["OK"])
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
      expect(subject.created_on).to eq(Time.parse("2004-12-20 13:34:34 UTC"))
    end
  end
  describe "#updated_on" do
    it do
      expect(subject.updated_on).to be_a(Time)
      expect(subject.updated_on).to eq(Time.parse("2008-12-20 19:25:54 UTC"))
    end
  end
  describe "#expires_on" do
    it do
      expect(subject.expires_on).to be_a(Time)
      expect(subject.expires_on).to eq(Time.parse("2009-12-20 13:34:34 UTC"))
    end
  end
  describe "#registrar" do
    it do
      expect(subject.registrar).to be_a(Whois::Parser::Registrar)
      expect(subject.registrar.id).to eq("R43-LRCC")
      expect(subject.registrar.name).to eq("GibNet Registrar")
      expect(subject.registrar.organization).to eq(nil)
      expect(subject.registrar.url).to eq(nil)
    end
  end
  describe "#registrant_contacts" do
    it do
      expect(subject.registrant_contacts).to be_a(Array)
      expect(subject.registrant_contacts.size).to eq(1)
      expect(subject.registrant_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.registrant_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_REGISTRANT)
      expect(subject.registrant_contacts[0].id).to eq("FR-1103549674779")
      expect(subject.registrant_contacts[0].name).to eq("Jimmy Imossi")
      expect(subject.registrant_contacts[0].organization).to eq("Broadband Gibraltar Limited")
      expect(subject.registrant_contacts[0].address).to eq("Suite 951\nEuroport")
      expect(subject.registrant_contacts[0].city).to eq("Gibraltar")
      expect(subject.registrant_contacts[0].zip).to eq("NA")
      expect(subject.registrant_contacts[0].state).to eq("")
      expect(subject.registrant_contacts[0].country_code).to eq("GI")
      expect(subject.registrant_contacts[0].phone).to eq("+350.47200")
      expect(subject.registrant_contacts[0].fax).to eq("+350.47272")
      expect(subject.registrant_contacts[0].email).to eq("jimossi@sapphire.gi")
    end
  end
  describe "#admin_contacts" do
    it do
      expect(subject.admin_contacts).to be_a(Array)
      expect(subject.admin_contacts.size).to eq(1)
      expect(subject.admin_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.admin_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_ADMINISTRATIVE)
      expect(subject.admin_contacts[0].id).to eq("FR-1103549674779")
      expect(subject.admin_contacts[0].name).to eq("Jimmy Imossi")
      expect(subject.admin_contacts[0].organization).to eq("Broadband Gibraltar Limited")
      expect(subject.admin_contacts[0].address).to eq("Suite 951\nEuroport")
      expect(subject.admin_contacts[0].city).to eq("Gibraltar")
      expect(subject.admin_contacts[0].zip).to eq("NA")
      expect(subject.admin_contacts[0].state).to eq("")
      expect(subject.admin_contacts[0].country_code).to eq("GI")
      expect(subject.admin_contacts[0].phone).to eq("+350.47200")
      expect(subject.admin_contacts[0].fax).to eq("+350.47272")
      expect(subject.admin_contacts[0].email).to eq("jimossi@sapphire.gi")
    end
  end
  describe "#technical_contacts" do
    it do
      expect(subject.technical_contacts).to be_a(Array)
      expect(subject.technical_contacts.size).to eq(1)
      expect(subject.technical_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.technical_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_TECHNICAL)
      expect(subject.technical_contacts[0].id).to eq("FR-10a223e2e4cf0")
      expect(subject.technical_contacts[0].name).to eq("Tech Dept")
      expect(subject.technical_contacts[0].organization).to eq("Broadband Gibraltar Ltd")
      expect(subject.technical_contacts[0].address).to eq("Suite 9.5.1\nEuroport")
      expect(subject.technical_contacts[0].city).to eq("N/A")
      expect(subject.technical_contacts[0].zip).to eq("N/A")
      expect(subject.technical_contacts[0].state).to eq("")
      expect(subject.technical_contacts[0].country_code).to eq("GI")
      expect(subject.technical_contacts[0].phone).to eq("+350.47200")
      expect(subject.technical_contacts[0].fax).to eq("+350.47271")
      expect(subject.technical_contacts[0].email).to eq("tech@sapphire.gi")
    end
  end
  describe "#nameservers" do
    it do
      expect(subject.nameservers).to be_a(Array)
      expect(subject.nameservers.size).to eq(2)
      expect(subject.nameservers[0]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[0].name).to eq("ns1-a.sapphire.gi")
      expect(subject.nameservers[1]).to be_a(Whois::Parser::Nameserver)
      expect(subject.nameservers[1].name).to eq("ns2-a.sapphire.gi")
    end
  end
end
