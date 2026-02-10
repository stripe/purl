//! Simple table formatting for CLI output.
//!
//! Clean, minimal tables with auto-calculated column widths.
//! No borders, just whitespace alignment.

use colored::{ColoredString, Colorize};

/// A simple table for CLI output.
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    /// Column widths (calculated on print)
    widths: Vec<usize>,
}

impl Table {
    /// Create a new table with the given headers.
    pub fn new(headers: &[&str]) -> Self {
        Self {
            headers: headers.iter().map(|s| s.to_string()).collect(),
            rows: Vec::new(),
            widths: Vec::new(),
        }
    }

    /// Add a row of data.
    pub fn row(&mut self, cells: &[&str]) -> &mut Self {
        self.rows
            .push(cells.iter().map(|s| s.to_string()).collect());
        self
    }

    /// Add a row with owned strings.
    #[allow(dead_code)]
    pub fn row_owned(&mut self, cells: Vec<String>) -> &mut Self {
        self.rows.push(cells);
        self
    }

    /// Calculate column widths based on content.
    fn calculate_widths(&mut self) {
        self.widths = self
            .headers
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let header_len = h.len();
                let max_cell_len = self
                    .rows
                    .iter()
                    .map(|row| row.get(i).map(|c| c.len()).unwrap_or(0))
                    .max()
                    .unwrap_or(0);
                header_len.max(max_cell_len)
            })
            .collect();
    }

    /// Print the table to stdout.
    pub fn print(&mut self) {
        self.calculate_widths();

        // Print headers (dimmed)
        let header_line: Vec<String> = self
            .headers
            .iter()
            .enumerate()
            .map(|(i, h)| format!("{:<width$}", h, width = self.widths[i]))
            .collect();
        println!("  {}", header_line.join("  ").dimmed());

        // Print rows
        for row in &self.rows {
            let cells: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(i, cell)| {
                    let width = self.widths.get(i).copied().unwrap_or(cell.len());
                    format!("{:<width$}", cell, width = width)
                })
                .collect();
            println!("  {}", cells.join("  "));
        }
    }

    /// Print with a custom formatter for each cell.
    /// The formatter receives (column_index, cell_value) and returns a ColoredString.
    pub fn print_with<F>(&mut self, formatter: F)
    where
        F: Fn(usize, &str) -> ColoredString,
    {
        self.calculate_widths();

        // Print headers (dimmed)
        let header_line: Vec<String> = self
            .headers
            .iter()
            .enumerate()
            .map(|(i, h)| format!("{:<width$}", h, width = self.widths[i]))
            .collect();
        println!("  {}", header_line.join("  ").dimmed());

        // Print rows with formatting
        for row in &self.rows {
            let cells: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(i, cell)| {
                    let width = self.widths.get(i).copied().unwrap_or(cell.len());
                    let formatted = formatter(i, cell);
                    // Pad after formatting (note: colored strings need special handling)
                    let visible_len = cell.len();
                    let padding = if width > visible_len {
                        " ".repeat(width - visible_len)
                    } else {
                        String::new()
                    };
                    format!("{}{}", formatted, padding)
                })
                .collect();
            println!("  {}", cells.join("  "));
        }
    }
}
