import unittest
from multilingual_ast_engine import MultilingualASTEngine, DependencyEdge

class TestMultilingualASTEngine(unittest.TestCase):

    def setUp(self):
        self.engine = MultilingualASTEngine()

    def test_python_symbol_extraction(self):
        py_code = """
def authenticate_user(username, password):
    pass

class UserSession:
    def get_token(self):
        pass
"""
        symbols = self.engine.extract_symbols_from_python("src/auth.py", py_code)
        self.assertGreaterEqual(len(symbols), 2)
        names = [s.symbol_name for s in symbols]
        self.assertIn("authenticate_user", names)
        self.assertIn("UserSession", names)

    def test_typescript_symbol_extraction(self):
        ts_code = """
export function parseClaims(raw: string): Claim[] { return []; }
export interface ClaimRecord { id: string; }
"""
        symbols = self.engine.extract_symbols_from_typescript("src/claims.ts", ts_code)
        self.assertEqual(len(symbols), 2)
        names = [s.symbol_name for s in symbols]
        self.assertIn("parseClaims", names)
        self.assertIn("ClaimRecord", names)

    def test_go_symbol_extraction(self):
        go_code = """
package pbm

func CalculateRebate(wac float64) float64 {
    return wac * 0.15
}

type RebatePlan struct {
    PlanID string
}
"""
        symbols = self.engine.extract_symbols_from_go("pkg/pbm/rebate.go", go_code)
        self.assertEqual(len(symbols), 2)
        names = [s.symbol_name for s in symbols]
        self.assertIn("CalculateRebate", names)
        self.assertIn("RebatePlan", names)

    def test_rust_symbol_extraction(self):
        rs_code = """
pub fn verify_signature(data: &[u8]) -> bool {
    true
}

pub trait TokenVerifier {
    fn verify(&self) -> bool;
}
"""
        symbols = self.engine.extract_symbols_from_rust("crates/auth/src/lib.rs", rs_code)
        self.assertEqual(len(symbols), 2)
        names = [s.symbol_name for s in symbols]
        self.assertIn("verify_signature", names)
        self.assertIn("TokenVerifier", names)

    def test_blast_radius_calculation(self):
        py_symbols = self.engine.extract_symbols_from_python("src/auth.py", "def login(): pass")
        ts_symbols = self.engine.extract_symbols_from_typescript("src/api.ts", "export function callLogin() {}")
        all_changed = py_symbols + ts_symbols

        edges = [
            DependencyEdge(source_symbol_id=ts_symbols[0].symbol_id, target_symbol_id=py_symbols[0].symbol_id, edge_type="calls")
        ]

        res = self.engine.compute_blast_radius(all_changed, edges)
        self.assertTrue(res.cross_language_boundary)
        self.assertEqual(res.impacted_symbols_count, 2)
        self.assertTrue(res.smt_invariant_verified)

if __name__ == "__main__":
    unittest.main()
