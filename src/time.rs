use {
    jiff::{
        Timestamp,
        tz::TimeZone,
    },
    rocket::response::content::RawHtml,
    rocket_util::html,
};

pub(crate) struct DateTimeFormat {
    pub(crate) long: bool,
    pub(crate) running_text: bool,
}

pub(crate) fn format_datetime(datetime: impl Into<Timestamp>, format: DateTimeFormat) -> RawHtml<String> {
    let datetime = datetime.into();
    let utc = datetime.to_zoned(TimeZone::UTC);
    let paris = datetime.in_tz("Europe/Paris").unwrap();
    let new_york = datetime.in_tz("America/New_York").unwrap();
    let paris_same_date = paris.date() == utc.date();
    let new_york_same_date = new_york.date() == utc.date();
    let paris = paris.strftime(if paris_same_date { "%H:%M %Z" } else { "%a %H:%M %Z" }).to_string();
    let new_york = new_york.strftime(match (new_york_same_date, new_york.minute() == 0) {
        (false, false) => "%a %-I:%M %p %Z",
        (false, true) => "%a %-I%p %Z",
        (true, false) => "%-I:%M %p %Z",
        (true, true) => "%-I%p %Z",
    }).to_string();
    html! {
        //TODO format as a link, e.g. https://hammertime.cyou/?t=1723402800.000
        span(class = "datetime", data_timestamp = datetime.as_millisecond(), data_long = format.long.to_string()) {
            : utc.strftime("%A, %B %-d, %Y, %H:%M UTC").to_string();
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
