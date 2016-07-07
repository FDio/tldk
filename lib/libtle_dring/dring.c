/*
 * Copyright (c) 2016  Intel Corporation.
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

#include <tle_dring.h>

static const char *
str_drb_dummy(const struct tle_dring *dr, const struct tle_drb *db)
{
	return (db == &dr->dummy) ? "<dummy>" : "";
}

static const char *
str_obj_state(const struct tle_dring *dr, const struct tle_drb *db,
	uint32_t idx)
{
	if (db->start + idx < dr->cons.tail)
		return "<stale>";
	else if (db->start + idx >= dr->prod.tail)
		return "<free>";
	else
		return NULL;
}

static void
drb_obj_dump(FILE *f, int32_t verb, const struct tle_dring *dr,
	const struct tle_drb *db, uint32_t idx)
{
	const char *st;

	st = str_obj_state(dr, db, idx);

	/* pointer to object is valid, dump it. */
	if (st == NULL)
		fprintf(f, "\t\t\t\t%u:%p\n", db->start + idx, db->objs[idx]);

	/* dump in verbose mode only. */
	else if (verb > 0)
		fprintf(f, "\t\t\t\t%u:%p%s\n",
				db->start + idx, db->objs[idx], st);
}

static void
drb_dump(FILE *f, int32_t verb, const struct tle_dring *dr,
	const struct tle_drb *db)
{
	uint32_t i;

	fprintf(f, "\t\t@%p%s={\n", db, str_drb_dummy(dr, db));
	fprintf(f, "\t\t\tnext=%p,\n", db->next);
	fprintf(f, "\t\t\tsize=%u,\n", db->size);
	fprintf(f, "\t\t\tstart=%u,\n", db->start);

	fprintf(f, "\t\t\tobjs[]={\n");
	for (i = 0; i != db->size; i++)
		drb_obj_dump(f, verb, dr, db, i);
	fprintf(f, "\t\t\t},\n");

	fprintf(f, "\t\t},\n");
}

void
tle_dring_dump(FILE *f, int32_t verb, const struct tle_dring *dr)
{
	struct tle_drb *db;

	fprintf(f, "tle_dring@%p={\n", dr);
	fprintf(f, "\tflags=%#x,\n", dr->flags);

	fprintf(f, "\tprod={,\n");
	fprintf(f, "\t\thead=%u,\n", dr->prod.head);
	fprintf(f, "\t\ttail=%u,\n", dr->prod.tail);
	fprintf(f, "\t\tcrb=%p%s,\n", dr->prod.crb,
		str_drb_dummy(dr, dr->prod.crb));
	fprintf(f, "\t},\n");

	fprintf(f, "\tcons={,\n");
	fprintf(f, "\t\thead=%u,\n", dr->cons.head);
	fprintf(f, "\t\ttail=%u,\n", dr->cons.tail);
	fprintf(f, "\t\tcrb=%p%s,\n", dr->cons.crb,
		str_drb_dummy(dr, dr->cons.crb));
	fprintf(f, "\t},\n");

	fprintf(f, "\tdrbs[] = {\n");
	for (db = dr->prod.crb; db != NULL; db = db->next)
		drb_dump(f, verb, dr, db);
	fprintf(f, "\t},\n");

	fprintf(f, "};\n");
}
