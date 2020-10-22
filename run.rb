#!/usr/bin/env ruby

require 'google-cloud-build'
require 'google-cloud-container_analysis'
require 'slack-notifier'
require 'logger'

# ENV['WAIT_TIMER'] = 600
# ENV['GOOGLE_APPLICATION_CREDENTIALS'] = ".config/glcoud.json"
# ENV['SLACK_WEBHOOK'] = "https://hooks.slack.com/services/XXXX/YYYY/ABCD"
# ENV['SLACK_CHANNEL'] = "#alerts"
# ENV['SLACK_USER'] = "alerts"

wait_timer = ENV['WAIT_TIMER'].nil? ? 600 : ENV['WAIT_TIMER'].to_i
vuln_wait_timer = ENV['VULN_WAIT_TIMER'].nil? ? 180 : ENV['VULN_WAIT_TIMER'].to_i
logger = Logger.new(STDOUT)

gcb = Google::Cloud::Build.cloud_build
gcr = Google::Cloud::ContainerAnalysis.container_analysis.grafeas_client
project_id = JSON.load(File.open(ENV['GOOGLE_APPLICATION_CREDENTIALS']))['project_id']

current_build_ts = Time.now
while wait_timer > 0
  logger.debug("#{current_build_ts - wait_timer - vuln_wait_timer} -- #{current_build_ts - vuln_wait_timer}")
  gcb.list_builds(project_id: project_id, filter: 'status="SUCCESS"', page_size: 200).each do |build|
    if Time.at(build.finish_time.seconds) >= (current_build_ts - wait_timer - vuln_wait_timer) && Time.at(build.finish_time.seconds) <= (current_build_ts - vuln_wait_timer)
      image_id = build.results.images[0].name.sub(/:(.*)$/, '')
      image_sha = build.results.images[0].digest
      image_tag = build['images'][0].match(/:(.*)$/)[1]

      vulns = { 'CRITICAL' =>0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0 }
      gcr.list_occurrences(parent: gcr.project_path(project: project_id), filter: "kind = \"VULNERABILITY\" AND resourceUrl = \"https://#{image_id}@#{image_sha}\"").each do |occurrence|
        severity = occurrence['vulnerability']['effective_severity'].to_s
        case severity
        when "CRITICAL"
          vulns['CRITICAL'] += 1
        when "HIGH"
          vulns['HIGH'] += 1
        when "MEDIUM"
          vulns['MEDIUM'] += 1
        when "LOW"
          vulns['LOW'] += 1
        end
      end

      logger.info("#{Time.at(build.finish_time.seconds)} https://#{image_id}@#{image_sha} #{vulns}")

      notifier = Slack::Notifier.new ENV['SLACK_WEBHOOK'], channel: ENV['SLACK_CHANNEL'], username: ENV['SLACK_USER']
      if vulns['HIGH'] == 0 && vulns['CRITICAL'] == 0
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
        title: "#{image_id}:#{image_tag}",
        title_link: "https://#{image_id}@#{image_sha}",
        color: "#{message_colour}",
        fields: [{
          title: "Critical",
          value: "#{vulns['CRITICAL']}",
          short: true
        },{
          title: "High",
          value: "#{vulns['HIGH']}",
          short: true
        },{
          title: "Medium",
          value: "#{vulns['MEDIUM']}",
          short: true
        },{
          title: "Low",
          value: "#{vulns['LOW']}",
          short: true
        }],
        author_name: "<https://console.cloud.google.com/gcr/images/#{project_id}|ContainerAnalysis>",
        author_link: "https://#{image_id}@#{image_sha}",
        footer: "<#{build['log_url']}|Cloud Builder>",
        footer_icon: "https://avatars2.githubusercontent.com/u/21046548?s=400&v=4",
        ts: "#{build.finish_time.seconds}"
      }
      notifier.post text: "", attachments: [message]
    end
  end
  current_build_ts += wait_timer
  sleep wait_timer
end
