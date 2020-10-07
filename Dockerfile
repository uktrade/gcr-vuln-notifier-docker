FROM ruby:2.7

COPY Gemfile* /tmp/
RUN gem install bundler && \
    bundle check || bundle install --gemfile=/tmp/Gemfile

COPY run.* /

ENTRYPOINT ["/run.sh"]
