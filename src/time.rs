use {
    chrono::prelude::*,
    chrono_tz::{
        America,
        Europe,
    },
    rocket::response::content::RawHtml,
    rocket_util::html,
};

pub(crate) struct DateTimeFormat {
    pub(crate) long: bool,
    pub(crate) running_text: bool,
}

pub(crate) fn format_datetime<Z: TimeZone>(datetime: DateTime<Z>, format: DateTimeFormat) -> RawHtml<String> {
    let utc = datetime.to_utc();
    let paris = datetime.with_timezone(&Europe::Paris);
    let new_york = datetime.with_timezone(&America::New_York);
    let paris_same_date = paris.date_naive() == utc.date_naive();
    let new_york_same_date = new_york.date_naive() == utc.date_naive();
    let paris = paris.format(if paris_same_date { "%H:%M %Z" } else { "%A %H:%M %Z" }).to_string();
    let new_york = new_york.format(match (new_york_same_date, new_york.minute() == 0) {
        (false, false) => "%A %-I:%M %p %Z",
        (false, true) => "%A %-I%p %Z",
        (true, false) => "%-I:%M %p %Z",
        (true, true) => "%-I%p %Z",
    }).to_string();
    html! {
        //TODO once https://github.com/WentTheFox/SledgeHammerTime is out of beta and https://github.com/WentTheFox/SledgeHammerTime/issues/2 is fixed, format as a link, e.g. https://hammertime.cyou/?t=1723402800.000
        span(class = "datetime", data_timestamp = datetime.timestamp_millis(), data_long = format.long.to_string()) {
            : utc.format("%A, %B %-d, %Y, %H:%M UTC").to_string();
            @if format.running_text {
                : " (";
            } else {
                : " • ";
            }
            @if new_york_same_date && !paris_same_date {
                : new_york;
            } else {
                : paris;
            }
            @if format.running_text {
                : ", ";
            } else {
                : " • ";
            }
            @if new_york_same_date && !paris_same_date {
                : paris;
            } else {
                : new_york;
            }
            @if format.running_text {
                : ")";
            }
        }
    }
}
