use plotters::{
    chart::ChartBuilder,
    prelude::*,
    style::{
        text_anchor::{HPos, Pos, VPos},
        Color,
        IntoFont,
        RGBColor,
        TextStyle,
        WHITE
    }
};

#[derive(Debug, Clone, Copy)]
pub enum MemOp {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MemTracker {
    pub read: u64,
    pub write: u64,
}

// Track the operations used in each iteration
// This is used to verify that we have a good distribution
// in branches and memory operations
#[derive(Debug)]
pub struct OpsTracker {
    // branches id used at each iteration
    branches: [usize; 16],
    // memory operations used at each iteration
    // first Vec represents the scratchpad with each index
    // inner Vec represents the memory operations used at each index
    mem_ops: Vec<MemTracker>,
}

impl OpsTracker {
    pub fn new(scratchpad: usize) -> Self {
        Self {
            branches: [0; 16],
            mem_ops: vec![Default::default(); scratchpad],
        }
    }

    pub fn add_branch(&mut self, branch: u8) {
        self.branches[branch as usize] += 1;
    }

    pub fn add_mem_op(&mut self, index: usize, mem_op: MemOp) {
        let tracker = &mut self.mem_ops[index];
        match mem_op {
            MemOp::Read => tracker.read += 1,
            MemOp::Write => tracker.write += 1,
        }
    }

    pub fn get_branches(&self) -> &[usize; 16] {
        &self.branches
    }

    pub fn get_mem_ops(&self) -> &Vec<MemTracker> {
        &self.mem_ops
    }

    /// Generate a percentage-based heatmap of branch usage
    pub fn generate_branch_distribution(&self, output_path: &str) -> Result<(), anyhow::Error> {
        let total: usize = self.branches.iter().sum();
        let total = total.max(1);

        let percentages: Vec<f64> = self.branches
            .iter()
            .map(|&b| (b as f64 / total as f64) * 100.0)
            .collect();

        // Choose a reasonable y max (at least a little above the tallest bar)
        let max_val = percentages
            .iter()
            .cloned()
            .fold(0.0_f64, f64::max)
            .max(10.0);

        // Create drawing area
        let root = BitMapBackend::new(output_path, (1000, 600)).into_drawing_area();
        root.fill(&WHITE)?;

        // Use f64 for x-range so we can put label at i + 0.5
        let mut chart = ChartBuilder::on(&root)
            .caption("Branch Usage Distribution (%)", ("sans-serif", 30))
            .margin(20)
            .x_label_area_size(40)
            .y_label_area_size(60)
            .build_cartesian_2d(0f64..16f64, 0f64..(max_val * 1.12))?; // leave headroom for labels

        chart
            .configure_mesh()
            .x_labels(16)
            .x_label_formatter(&|x| format!("{}", *x as usize))
            .x_desc("Branch ID")
            .y_desc("Usage (%)")
            .axis_desc_style(("sans-serif", 20))
            .draw()?;

        // Bar color
        let bar_style = RGBColor(30, 120, 200).filled();

        // Draw bars using f64 coordinates
        for (i, &pct) in percentages.iter().enumerate() {
            let x0 = i as f64;
            let x1 = x0 + 0.9; // slightly narrower than 1.0 for spacing
            chart.draw_series(std::iter::once(Rectangle::new(
                [(x0, 0.0), (x1, pct)],
                bar_style,
            )))?;
        }

        // Prepare a TextStyle and position it anchored to center above the bar
        let label_style = TextStyle::from(("sans-serif", 14).into_font())
            .pos(Pos::new(HPos::Center, VPos::Bottom));

        // Draw labels
        for (i, &pct) in percentages.iter().enumerate() {
            let x_center = i as f64 + 0.45; // center given x1 = x0 + 0.9
            let y = pct + (max_val * 0.02); // small offset above the bar
            chart.draw_series(std::iter::once(Text::new(
                format!("{:.1}%", pct),
                (x_center, y),
                label_style.clone(),
            )))?;
        }

        root.present()?;
        Ok(())
    }

pub fn generate_memory_usage_graph(
    &self,
    output_path: &str,
    ma_window: usize,
) -> Result<(), anyhow::Error> {
    use plotters::prelude::*;

    let scratchpad_size = self.mem_ops.len();
    let mut read_counts = vec![0usize; scratchpad_size];
    let mut write_counts = vec![0usize; scratchpad_size];

    for (i, ops) in self.mem_ops.iter().enumerate() {
        read_counts[i] = ops.read as usize;
        write_counts[i] = ops.write as usize;
    }

    // ---- zero-phase moving average (filtfilt for a boxcar) ----

    #[inline]
    fn ma_forward_usize(data: &[usize], w: usize) -> Vec<f64> {
        let w = w.max(1);
        let mut out = vec![0.0; data.len()];
        let mut sum: u64 = 0;
        for i in 0..data.len() {
            sum += data[i] as u64;
            if i >= w { sum -= data[i - w] as u64; }
            let denom = (i + 1).min(w) as f64;
            out[i] = sum as f64 / denom;
        }
        out
    }

    #[inline]
    fn ma_forward_f64(data: &[f64], w: usize) -> Vec<f64> {
        let w = w.max(1);
        let mut out = vec![0.0; data.len()];
        let mut sum: f64 = 0.0;
        for i in 0..data.len() {
            sum += data[i];
            if i >= w { sum -= data[i - w]; }
            let denom = (i + 1).min(w) as f64;
            out[i] = sum / denom;
        }
        out
    }

    #[inline]
    fn filtfilt_ma_usize(data: &[usize], w: usize) -> Vec<f64> {
        let fwd = ma_forward_usize(data, w);
        let mut rev = fwd.clone();
        rev.reverse();
        let rev2 = ma_forward_f64(&rev, w);
        let mut out = rev2;
        out.reverse();
        out
    }

    let read_ma = filtfilt_ma_usize(&read_counts, ma_window);
    let write_ma = filtfilt_ma_usize(&write_counts, ma_window);

    // Y-axis
    let counts_max = read_counts.iter().zip(write_counts.iter())
        .map(|(&r, &w)| r.max(w))
        .max()
        .unwrap_or(1) as f64;
    let ma_max = read_ma.iter().cloned().fold(0.0, f64::max)
        .max(write_ma.iter().cloned().fold(0.0, f64::max));
    let y_max = counts_max.max(ma_max) * 1.15;

    // ---- plot ----
    let root = BitMapBackend::new(output_path, (1920, 1080)).into_drawing_area();
    root.fill(&WHITE)?;

    let mut chart = ChartBuilder::on(&root)
        .caption(
            format!("Memory Accesses per Index (Read/Write + filtfilt MA({}))", ma_window.max(1)),
            ("sans-serif", 28),
        )
        .margin(20)
        .x_label_area_size(40)
        .y_label_area_size(60)
        .build_cartesian_2d(0f64..scratchpad_size as f64, 0f64..y_max)?;

    chart
        .configure_mesh()
        .x_labels(20)
        .x_label_formatter(&|x| format!("{}", *x as usize))
        .x_desc("Memory Index")
        .y_desc("Access Count")
        .axis_desc_style(("sans-serif", 18))
        .draw()?;

    let read_fill = RGBColor(30, 144, 255).filled();
    let write_fill = RGBColor(220, 50, 47).filled();
    let read_line = RGBColor(30, 144, 255);
    let write_line = RGBColor(220, 50, 47);

    let avg_read_line = RGBColor(100, 180, 255);
    let avg_write_line = RGBColor(255, 100, 100);

    let bar_width = 1.0;

    for i in 0..scratchpad_size {
        let x0 = i as f64 - bar_width / 2.0;
        let x1 = i as f64 + bar_width / 2.0;
        let r = read_counts[i] as f64;
        let w = write_counts[i] as f64;

        if r > w {
            chart.draw_series(std::iter::once(Rectangle::new([(x0, 0.0), (x1, r)], read_fill.clone())))?;
            if w > 0.0 {
                chart.draw_series(std::iter::once(Rectangle::new([(x0, 0.0), (x1, w)], write_fill.clone())))?;
            }
        } else {
            chart.draw_series(std::iter::once(Rectangle::new([(x0, 0.0), (x1, w)], write_fill.clone())))?;
            if r > 0.0 {
                chart.draw_series(std::iter::once(Rectangle::new([(x0, 0.0), (x1, r)], read_fill.clone())))?;
            }
        }
    }

    // Zero-phase MA overlays
    chart.draw_series(LineSeries::new(
        (0..scratchpad_size).map(|i| (i as f64, read_ma[i])),
        ShapeStyle::from(&avg_read_line).stroke_width(3),
    ))?.label(format!("Read MA_filtfilt({})", ma_window.max(1)));

    chart.draw_series(LineSeries::new(
        (0..scratchpad_size).map(|i| (i as f64, write_ma[i])),
        ShapeStyle::from(&avg_write_line).stroke_width(3),
    ))?.label(format!("Write MA_filtfilt({})", ma_window.max(1)));

    // Legend
    chart
        .draw_series(std::iter::once(Rectangle::new([(0.0, 0.0), (0.0, 0.0)], read_fill.clone())))?
        .label("Read")
        .legend(move |(x, y)| Rectangle::new([(x, y - 5), (x + 10, y + 5)], read_fill.clone()));
    chart
        .draw_series(std::iter::once(Rectangle::new([(0.0, 0.0), (0.0, 0.0)], write_fill.clone())))?
        .label("Write")
        .legend(move |(x, y)| Rectangle::new([(x, y - 5), (x + 10, y + 5)], write_fill.clone()));
    chart
        .draw_series(std::iter::once(PathElement::new(
            vec![(0.0, 0.0), (0.0, 0.0)],
            ShapeStyle::from(&read_line).stroke_width(3),
        )))?
        .label(format!("Read MA_filtfilt({})", ma_window.max(1)))
        .legend(move |(x, y)| PathElement::new(
            vec![(x, y), (x + 14, y)],
            ShapeStyle::from(&read_line).stroke_width(3),
        ));
    chart
        .draw_series(std::iter::once(PathElement::new(
            vec![(0.0, 0.0), (0.0, 0.0)],
            ShapeStyle::from(&write_line).stroke_width(3),
        )))?
        .label(format!("Write MA_filtfilt({})", ma_window.max(1)))
        .legend(move |(x, y)| PathElement::new(
            vec![(x, y), (x + 14, y)],
            ShapeStyle::from(&write_line).stroke_width(3),
        ));

    chart
        .configure_series_labels()
        .position(SeriesLabelPosition::UpperRight)
        .border_style(&BLACK)
        .background_style(WHITE.mix(0.8))
        .draw()?;

    root.present()?;
    Ok(())
}

}