"""Allow ``python -m agg_cp`` -- delegates to migrate.main()."""
import sys

from agg_cp.migrate import main

sys.exit(main())
