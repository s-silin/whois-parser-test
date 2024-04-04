require 'spec_helper'
require 'whois/parsers/whois.arin.net.rb'

describe Whois::Parsers::WhoisArinNet, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.arin.net/status_registered.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
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
      expect(subject.created_on).to eq(Time.parse('2011-12-08'))
    end
  end

  describe "#updated_on" do
    it do
      expect(subject.updated_on).to eq(Time.parse('2017-1-28'))
    end
  end

  describe "#expires_on" do
    it do
      expect { subject.expires_on }.to raise_error(Whois::AttributeNotSupported)
    end
  end

  describe "#nameservers" do
    it do
      expect { subject.nameservers }.to raise_error(Whois::AttributeNotSupported)
    end
  end

  describe '#response_throttled?' do
    it do
      expect(subject.response_throttled?).to eq(false)
    end
  end

  describe '#registrant_contacts' do
    it do
      expect(subject.registrant_contacts).to be_a(Array)
      expect(subject.registrant_contacts[0].id).to eq(nil)
      expect(subject.registrant_contacts[0].type).to eq(1)
      expect(subject.registrant_contacts[0].name)
        .to eq('Amazon AWS Network Operations')
      expect(subject.registrant_contacts[0].organization)
        .to eq('Amazon Technologies Inc.')
      expect(subject.registrant_contacts[0].address).to eq('410 Terry Ave N.')
      expect(subject.registrant_contacts[0].city).to eq('Seattle')
      expect(subject.registrant_contacts[0].zip).to eq('98109')
      expect(subject.registrant_contacts[0].state).to eq('WA')
      expect(subject.registrant_contacts[0].country).to eq(nil)
      expect(subject.registrant_contacts[0].country_code).to eq('US')
      expect(subject.registrant_contacts[0].phone).to eq('+1-206-266-4064')
      expect(subject.registrant_contacts[0].fax).to eq(nil)
      expect(subject.registrant_contacts[0].email)
        .to eq('amzn-noc-contact@amazon.com')
      expect(subject.registrant_contacts[0].url).to eq(nil)
      expect(subject.registrant_contacts[0].created_on).to eq(nil)
      expect(subject.registrant_contacts[0].updated_on).to eq(nil)
    end
  end

  describe '#admin_contacts' do
    it do
      expect(subject.admin_contacts).to be_a(Array)
      expect(subject.admin_contacts[0].id).to eq(nil)
      expect(subject.admin_contacts[0].type).to eq(2)
      expect(subject.admin_contacts[0].name)
        .to eq('Amazon EC2 Abuse')
      expect(subject.admin_contacts[0].organization)
        .to eq('Amazon Technologies Inc.')
      expect(subject.admin_contacts[0].address).to eq('410 Terry Ave N.')
      expect(subject.admin_contacts[0].city).to eq('Seattle')
      expect(subject.admin_contacts[0].zip).to eq('98109')
      expect(subject.admin_contacts[0].state).to eq('WA')
      expect(subject.admin_contacts[0].country).to eq(nil)
      expect(subject.admin_contacts[0].country_code).to eq('US')
      expect(subject.admin_contacts[0].phone).to eq('+1-206-266-4064')
      expect(subject.admin_contacts[0].fax).to eq(nil)
      expect(subject.admin_contacts[0].email)
        .to eq('abuse@amazonaws.com')
      expect(subject.admin_contacts[0].url).to eq(nil)
      expect(subject.admin_contacts[0].created_on).to eq(nil)
      expect(subject.admin_contacts[0].updated_on).to eq(nil)
    end
  end

  describe '#technical_contacts' do
    it do
      expect(subject.technical_contacts).to be_a(Array)
      expect(subject.technical_contacts[0].id).to eq(nil)
      expect(subject.technical_contacts[0].type).to eq(3)
      expect(subject.technical_contacts[0].name)
        .to eq('Amazon EC2 Network Operations')
      expect(subject.technical_contacts[0].organization)
        .to eq('Amazon Technologies Inc.')
      expect(subject.technical_contacts[0].address).to eq('410 Terry Ave N.')
      expect(subject.technical_contacts[0].city).to eq('Seattle')
      expect(subject.technical_contacts[0].zip).to eq('98109')
      expect(subject.technical_contacts[0].state).to eq('WA')
      expect(subject.technical_contacts[0].country).to eq(nil)
      expect(subject.technical_contacts[0].country_code).to eq('US')
      expect(subject.technical_contacts[0].phone).to eq('+1-206-266-4064')
      expect(subject.technical_contacts[0].fax).to eq(nil)
      expect(subject.technical_contacts[0].email)
        .to eq('amzn-noc-contact@amazon.com')
      expect(subject.technical_contacts[0].url).to eq(nil)
      expect(subject.technical_contacts[0].created_on).to eq(nil)
      expect(subject.technical_contacts[0].updated_on).to eq(nil)
    end
  end
end
