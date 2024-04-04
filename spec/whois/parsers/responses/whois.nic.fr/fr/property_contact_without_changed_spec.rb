# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.nic.fr/fr/property_contact_without_changed.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.nic.fr.rb'

describe Whois::Parsers::WhoisNicFr, "property_contact_without_changed.expected" do

  subject do
    file = fixture("responses", "whois.nic.fr/fr/property_contact_without_changed.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#admin_contacts" do
    it do
      expect(subject.admin_contacts).to be_a(Array)
      expect(subject.admin_contacts.size).to eq(1)
      expect(subject.admin_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.admin_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_ADMINISTRATIVE)
      expect(subject.admin_contacts[0].id).to eq("JMR39-FRNIC")
      expect(subject.admin_contacts[0].name).to eq("Jean Marc Raimondo")
      expect(subject.admin_contacts[0].organization).to eq("1C2")
      expect(subject.admin_contacts[0].address).to eq("20-22, rue Louis Armand\n75015 Paris")
      expect(subject.admin_contacts[0].city).to eq(nil)
      expect(subject.admin_contacts[0].zip).to eq(nil)
      expect(subject.admin_contacts[0].state).to eq(nil)
      expect(subject.admin_contacts[0].country).to eq(nil)
      expect(subject.admin_contacts[0].country_code).to eq("FR")
      expect(subject.admin_contacts[0].phone).to eq("+33 1 30 62 40 06")
      expect(subject.admin_contacts[0].fax).to eq(nil)
      expect(subject.admin_contacts[0].email).to eq("jmr@1c2.com")
      expect(subject.admin_contacts[0].updated_on).to eq(nil)
    end
  end
end
