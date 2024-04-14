package vn.rananu.util;

import java.time.Instant;
import java.time.LocalDate;
import java.time.YearMonth;
import java.util.ArrayList;
import java.util.List;

public class LocalDateUtils {
    public static List<LocalDate> daysBetween(LocalDate fromDate, LocalDate toDate) {
        List<LocalDate> localDates = new ArrayList<>();
        localDates.add(fromDate);
        LocalDate localDate = fromDate;
        while (localDate.isBefore(toDate)) {
            localDate = localDate.plusDays(1);
            localDates.add(localDate);
        }
        return localDates;
    }

    public static List<String> monthsBetween(YearMonth from, YearMonth to) {
        List<String> months = new ArrayList<>();
        months.add(from.toString());
        YearMonth yearMonth = from;
        while (yearMonth.isBefore(to)) {
            yearMonth = yearMonth.plusMonths(1);
            months.add(yearMonth.toString());
        }
        return months;
    }
}
