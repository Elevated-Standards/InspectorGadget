#!/bin/bash

# Get the current year
YEAR=$(date +"%Y")

# Get the current month name
MONTH=$(date +"%B")

# Get the current day of the month
DAY=$(date +"%d")

# Calculate the start date as the first day of the current month
# Get the current date, subtract days to get the previous month
START_DATE=$(date -u -d "-$((DAY - 1)) days" +"%Y-%m-%dT%H:%M:%SZ")

# Get the current date and time in ISO 8601 format
END_DATE=$(date -u +"%H:%M:%SZT%Y-%m-%d")

# Print the values (optional)
echo "Year: $YEAR"
echo "Month: $MONTH"
echo "Day: $DAY"
echo "Start Date: $START_DATE"
echo "End Date: $END_DATE"