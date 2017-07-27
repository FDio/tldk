/*
 * Copyright (c) 2016-2017  Intel Corporation.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "test_tle_dring.h"

TEST_F(dring, test_dring_st)
{
	printf("%s started;\n", __func__);

	tle_dring_reset(&dr, 0);
	r = init_drb_ring(OBJ_NUM);

	ASSERT_NE(r, (void *) NULL) << "Out of memory";

	tle_dring_dump(stdout, 1, &dr);

	memset(&arg, 0, sizeof(arg));
	arg[0].dr = &dr;
	arg[0].r = r;
	arg[0].iter = ITER_NUM;
	arg[0].enq_type = SINGLE;
	arg[0].deq_type = SINGLE;
	rc = test_dring_enq_deq(&arg[0]);

	rc = (rc != 0) ? rc : (arg[0].enq != arg[0].deq);
	printf("%s finished with status: %s(%d);\n",
		__func__, strerror(-rc), rc);

	tle_dring_dump(stdout, rc != 0, &dr);
	fini_drb_ring(r);
	EXPECT_EQ(rc, 0);
}


TEST_F(dring ,test_dring_mp_mc)
{
	rc = test_dring_mt(MULTI, MULTI, MULTI, MULTI);
	EXPECT_EQ(rc, 0);
}

TEST_F(dring, test_dring_mp_sc)
{
	rc = test_dring_mt(MULTI, SINGLE, MULTI, NONE);
	EXPECT_EQ(rc, 0);
}

TEST_F(dring, test_dring_sp_mc)
{
	rc = test_dring_mt(SINGLE, MULTI, NONE, MULTI);
	EXPECT_EQ(rc, 0);
}
