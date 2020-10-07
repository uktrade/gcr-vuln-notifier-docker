#!/usr/bin/env ruby

require 'gcloud'
require 'slack-notifier'

# ENV['GOOGLE_CLOUD_KEYFILE'] = ".config/glcoud.json"
# ENV['SLACK_WEBHOOK'] = "https://hooks.slack.com/services/XXXX/YYYY/ABCD"
# ENV['SLACK_CHANNEL'] = "#alerts"
# ENV['SLACK_USER'] = "alerts"

gcb = Google::Cloud::Build.cloud_build
gcr = Google::Cloud::ContainerAnalysis.container_analysis.grafeas_client
project_id = JSON.load(File.open(ENV['GOOGLE_CLOUD_KEYFILE']))['project_id']

gcb.list_builds(project_id: project_id, filter: 'status="SUCCESS"', page_size: 500).each do |build|
  if Time.at(build.finish_time.seconds) >= (Time.now - 900)
    image_id = build.results.images[0].name
    image_sha = build.results.images[0].digest
    puts "#{image_id}@#{image_sha}"

    vulns = { 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0 }
    gcr.list_occurrences(parent: gcr.project_path(project: project_id), filter: "resourceUrl = \"https://#{image_id}@#{image_sha}\" AND kind = \"VULNERABILITY\"").each do |occurrence|
      severity = occurrence['vulnerability']['effective_severity'].to_s
      case severity
      when "HIGH"
        vulns['HIGH'] += 1
      when "MEDIUM"
        vulns['MEDIUM'] += 1
      when "LOW"
        vulns['LOW'] += 1
      end
    end
    puts "Found #{vulns}"

    notifier = Slack::Notifier.new ENV['SLACK_WEBHOOK'], channel: ENV['SLACK_CHANNEL'], username: ENV['SLACK_USER']
    if vulns['HIGH'] == 0
      if vulns['MEDIUM'] == 0
        message_colour = "good"
      else
        message_colour = "warning"
      end
    else
      message_colour = "danger"
    end
    message = {
      fallback: "https://#{image_id}@#{image_sha}",
      title: "#{image_id}@#{image_sha}",
      title_link: "https://#{image_id}@#{image_sha}",
      color: "#{message_colour}",
      fields: [{
        title: "High Severity",
        value: "#{vulns['HIGH']}",
        short: true
      },{
        title: "Medium Severity",
        value: "#{vulns['MEDIUM']}",
        short: true
      },{
        title: "Low Severity",
        value: "#{vulns['LOW']}",
        short: true
      }],
      author_name: "#{project_id}",
      author_link: "https://#{image_id}@#{image_sha}",
      footer: "#{build['log_url']}",
      footer_icon: "https://avatars2.githubusercontent.com/u/21046548?s=400&v=4",
      ts: "#{build.finish_time.seconds}"
    }
    notifier.post text: "", attachments: [message]
  end
end
