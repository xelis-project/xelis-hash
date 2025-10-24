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
    mem_ops: Vec<Vec<MemOp>>,
}

impl OpsTracker {
    pub fn new(scratchpad: usize) -> Self {
        Self {
            branches: [0; 16],
            mem_ops: vec![Vec::new(); scratchpad],
        }
    }

    pub fn add_branch(&mut self, branch: u8) {
        self.branches[branch as usize] += 1;
    }

    pub fn add_mem_op(&mut self, index: usize, mem_op: MemOp) {
        self.mem_ops[index].push(mem_op);
    }

    pub fn get_branches(&self) -> &[usize; 16] {
        &self.branches
    }

    pub fn get_mem_ops(&self) -> &Vec<Vec<MemOp>> {
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

     /// Generate a grouped bar chart showing memory usage per index, split by Read and Write
    pub fn generate_memory_usage_graph(&self, output_path: &str) -> Result<(), anyhow::Error> {
             let scratchpad_size = self.mem_ops.len();
        let mut read_counts = vec![0usize; scratchpad_size];
        let mut write_counts = vec![0usize; scratchpad_size];

        // Count reads and writes
        for (i, ops) in self.mem_ops.iter().enumerate() {
            for &op in ops {
                match op {
                    MemOp::Read => read_counts[i] += 1,
                    MemOp::Write => write_counts[i] += 1,
                }
            }
        }

        // Find max value for Y-axis
        let max_val = read_counts
            .iter()
            .zip(write_counts.iter())
            .map(|(&r, &w)| r.max(w))
            .max()
            .unwrap_or(1) as f64;

        let root = BitMapBackend::new(output_path, (1920, 1080)).into_drawing_area();
        root.fill(&WHITE)?;

        let mut chart = ChartBuilder::on(&root)
            .caption("Memory Accesses per Index (Stacked Read/Write)", ("sans-serif", 28))
            .margin(20)
            .x_label_area_size(40)
            .y_label_area_size(60)
            .build_cartesian_2d(0f64..scratchpad_size as f64, 0f64..(max_val * 1.15))?;

        chart
            .configure_mesh()
            .x_labels(20)
            .x_label_formatter(&|x| format!("{}", *x as usize))
            .x_desc("Memory Index")
            .y_desc("Access Count")
            .axis_desc_style(("sans-serif", 18))
            .draw()?;

        let read_color = RGBColor(30, 144, 255).filled(); // blue
        let write_color = RGBColor(220, 50, 47).filled(); // red
        let bar_width = 1.0;

        // Draw stacked bars
        for i in 0..scratchpad_size {
            let x0 = i as f64 - bar_width / 2.0;
            let x1 = i as f64 + bar_width / 2.0;

            let read_height = read_counts[i] as f64;
            let write_height = write_counts[i] as f64;

            // Based on which is higher, draw that first for visibility
            // Then draw above it the lower one
            if read_height > write_height {
                // Draw read part
                chart.draw_series(std::iter::once(Rectangle::new(
                    [(x0, 0.0), (x1, read_height)],
                    read_color.clone(),
                )))?;

                if write_height > 0.0 {
                    // Draw write part on top of read
                    chart.draw_series(std::iter::once(Rectangle::new(
                        [(x0, 0.0), (x1, write_height)],
                        write_color.clone(),
                    )))?;
                }
            } else {
                // Draw write part
                chart.draw_series(std::iter::once(Rectangle::new(
                    [(x0, 0.0), (x1, write_height)],
                    write_color.clone(),
                )))?;

                if read_height > 0.0 {
                    // Draw read part on top of write
                    chart.draw_series(std::iter::once(Rectangle::new(
                        [(x0, 0.0), (x1, read_height)],
                        read_color.clone(),
                    )))?;
                }
            }
        }

        // Add **manual legend** using empty series just for labels
        chart
            .draw_series(std::iter::once(Rectangle::new([(0.0, 0.0), (0.0, 0.0)], read_color.clone())))
            ?.label("Read")
            .legend(|(x, y)| Rectangle::new([(x, y - 5), (x + 10, y + 5)], RGBColor(30, 144, 255).filled()));

        chart
            .draw_series(std::iter::once(Rectangle::new([(0.0, 0.0), (0.0, 0.0)], write_color.clone())))
            ?.label("Write")
            .legend(|(x, y)| Rectangle::new([(x, y - 5), (x + 10, y + 5)], RGBColor(220, 50, 47).filled()));

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