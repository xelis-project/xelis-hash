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
    // number of memory accesses done at each index
    mem_accesses: Vec<usize>,
}

impl OpsTracker {
    pub fn new(scratchpad: usize) -> Self {
        Self {
            branches: [0; 16],
            mem_ops: vec![Vec::new(); scratchpad],
            mem_accesses: vec![0; scratchpad],
        }
    }

    pub fn add_branch(&mut self, branch: u8) {
        self.branches[branch as usize] += 1;
    }

    pub fn add_mem_op(&mut self, index: usize, mem_op: MemOp) {
        self.mem_ops[index].push(mem_op);
        self.mem_accesses[index] += 1;
    }

    pub fn get_branches(&self) -> &[usize; 16] {
        &self.branches
    }

    pub fn get_mem_ops(&self) -> &Vec<Vec<MemOp>> {
        &self.mem_ops
    }

    pub fn get_mem_accesses(&self) -> &Vec<usize> {
        &self.mem_accesses
    }
}