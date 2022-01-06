#ifndef __TRUSTED_AI_CP_GADGETS__
#define __TRUSTED_AI_CP_GADGETS__

#include <zkdoc/src/trusted_ai_interactive_gadgets.hpp>
#include <zkdoc/src/trusted_ai_utility_gadgets.hpp>
#include <zkdoc/src/mimc_cipher_gadget.hpp>

using namespace libsnark;

namespace TrustedAI {
size_t partial_hash_sizes[] = {4, 8, 16, 32, 64};

template<typename FieldT>
class cp_filter_gadget : public gadget<FieldT> 
{
	public:
	cp_filter_gadget(
		protoboard<FieldT>& pb,
		const pb_variable_array<FieldT>& x,
		const pb_variable_array<FieldT>& f,
		const pb_variable_array<FieldT>& y,
		const pb_variable_array<FieldT>& X,
		const pb_variable_array<FieldT>& Y,
		const pb_variable_array<FieldT>& delta,
		const std::string& annotation_prefix=""
	);

	void generate_r1cs_constraints();

	void generate_r1cs_witness();

	private:
	pb_variable<FieldT> s_;
	pb_variable_array<FieldT> x_, X_;
	pb_variable<FieldT> t_;
	pb_variable_array<FieldT> y_, Y_;
	pb_variable_array<FieldT> f_;
	pb_variable_array<FieldT> delta_;
	pb_variable_array<FieldT> rho_;

	std::vector<size_enforcing_gadget<FieldT>> size_gadgets_;

};

template<typename FieldT>
cp_filter_gadget<FieldT>::cp_filter_gadget(
	protoboard<FieldT>& pb,
	const pb_variable_array<FieldT>& x,
	const pb_variable_array<FieldT>& f,
	const pb_variable_array<FieldT>& y,
	const pb_variable_array<FieldT>& X,
	const pb_variable_array<FieldT>& Y,
	const pb_variable_array<FieldT>& delta,
	const std::string& annotation_prefix):
	gadget<FieldT>(pb, annotation_prefix),
	x_(x),
	y_(y),
	s_(x[0]),
	X_(X),
	f_(f),
	t_(y[0]),
	Y_(Y),
	delta_(delta)
{
	rho_.allocate(this->pb, X_.size(), "rho");
	size_gadgets_.emplace_back(
		size_enforcing_gadget<FieldT>(
			this->pb,
			X_.size(),
			s_,
			rho_,
			"s<->rho"
		)
	);
	size_gadgets_.emplace_back(
		size_enforcing_gadget<FieldT>(
			this->pb,
			Y_.size(),
			t_,
			delta_,
			"t<->delta"
		)
	);


	for(size_t i=0; i < size_gadgets_.size(); ++i)
		size_gadgets_[i].allocate();
	
}

template<typename FieldT>
void cp_filter_gadget<FieldT>::generate_r1cs_constraints()
{
	for(size_t i=0; i < size_gadgets_.size(); ++i) size_gadgets_[i].generate_r1cs_constraints();

	for(size_t i=0; i < f_.size(); ++i)
	{
		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(f_[i], f_[i], f_[i]), "f is boolean"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(f_[i], 1 - rho_[i], 0), "f <= rho"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(X_[i], 1 - rho_[i], 0), "X is zero beyond rho"
		);


	}

	for(size_t i=0; i < X_.size(); ++i)
	{

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(x_[i+1], f_[i], X_[i]), "X[i]=f[i] o x[i+1]"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(y_[i+1], delta_[i], Y_[i]), "Y[i]= delta[i] o y[i+1]"
		);

	}



}

template<typename FieldT>
void cp_filter_gadget<FieldT>::generate_r1cs_witness()
{
	for(size_t i=0; i < size_gadgets_.size(); ++i) size_gadgets_[i].generate_r1cs_witness();
	for(size_t i=0; i < X_.size(); ++i)
	{
		this->pb.val(X_[i]) = this->pb.val(x_[i+1]) * this->pb.val(f_[i]);
		this->pb.val(Y_[i]) = this->pb.val(y_[i+1]) * this->pb.val(delta_[i]);
	}

}

template<typename FieldT>
class cp_aggregate_gadget : public gadget<FieldT>
{
	public:
	cp_aggregate_gadget(
		protoboard<FieldT>& pb,
		const pb_variable_array<FieldT>& x,				// in
		const pb_variable_array<FieldT>& y,				// in
		const pb_variable_array<FieldT>& z,				// in
		const pb_variable_array<FieldT>& XY,			// out
		const pb_variable_array<FieldT>& rhosigma,		// out
		const pb_variable_array<FieldT>& Zext,			// out
		const pb_variable_array<FieldT>& deltaext,		// out
		const std::string& annotation_prefix=""
	);

	void generate_r1cs_constraints();

	void generate_r1cs_witness();

	private:
	pb_variable_array<FieldT> x_, y_, z_, XY_, rhosigma_, Zext_, deltaext_;
	pb_variable_array<FieldT> rho_, sigma_, delta_;
	pb_variable<FieldT> s_, t_, w_;

	std::vector<size_enforcing_gadget<FieldT>> size_enforcers_;

};

template<typename FieldT>
cp_aggregate_gadget<FieldT>::cp_aggregate_gadget(
	protoboard<FieldT>& pb,
	const pb_variable_array<FieldT>& x,
	const pb_variable_array<FieldT>& y,
	const pb_variable_array<FieldT>& z,
	const pb_variable_array<FieldT>& XY,
	const pb_variable_array<FieldT>& rhosigma,
	const pb_variable_array<FieldT>& Zext,
	const pb_variable_array<FieldT>& deltaext,
	const std::string& annotation_prefix):
	gadget<FieldT>(pb, annotation_prefix),
	x_(x), y_(y), z_(z),
	s_(x[0]), t_(y[0]), w_(z[0]),
	XY_(XY), rhosigma_(rhosigma), Zext_(Zext),
	deltaext_(deltaext)
{
	size_t n = x_.size() - 1;
	rho_.allocate(this->pb, n, "rho");
	sigma_.allocate(this->pb, n, "sigma");
	delta_.allocate(this->pb, n, "delta");

	size_enforcers_.emplace_back(
		size_enforcing_gadget<FieldT>(
			this->pb,
			n,
			s_,
			rho_,
			"rhosize"
		)
	);

	size_enforcers_.emplace_back(
		size_enforcing_gadget<FieldT>(
			this->pb,
			n,
			t_,
			sigma_,
			"sigmasize"
		)
	);

	size_enforcers_.emplace_back(
		size_enforcing_gadget<FieldT>(
			this->pb,
			n,
			w_,
			delta_,
			"deltasize"
		)
	);

	for(size_t i=0; i < size_enforcers_.size(); ++i)
		size_enforcers_[i].allocate();
}	

template<typename FieldT>
void cp_aggregate_gadget<FieldT>::generate_r1cs_constraints()
{
	for(size_t i=0; i < size_enforcers_.size(); ++i)
		size_enforcers_[i].generate_r1cs_constraints();
	
	pb_variable_array<FieldT> X_(x_.begin() + 1, x_.end());
	pb_variable_array<FieldT> Y_(y_.begin() + 1, y_.end());
	pb_variable_array<FieldT> Z_(z_.begin() + 1, z_.end());
	// constraints:
	// X_ <= rho
	// Y_ <= sigma
	// Z_ <= delta
	for(size_t i=0; i < X_.size(); ++i)
	{
		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(X_[i], 1 - rho_[i], 0), "X <= rho"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(Y_[i], 1 - sigma_[i], 0), "Y <= sigma"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(Z_[i], 1 - delta_[i], 0), "Z <= delta"
		);
	}

	// XY = concat(X,Y)
	size_t n = X_.size();
	for(size_t i=0; i < n; ++i)
	{
		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(XY_[i], 1, X_[i]), "XY[i] = X[i]"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(XY_[i+n], 1, Y_[i]), "XY[i+n]=Y[i]"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(Zext_[i], 1, Z_[i]), "Zext[i] = Z[i]"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(Zext_[i+n], 1, 0), "Zext[i+n] = 0"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(deltaext_[i], 1, delta_[i]), "deltaext[i]=delta[i]"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(deltaext_[i+n], 1, 0), "deltaext[i+n] = 0"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(rhosigma_[i], 1, rho_[i]), "rhosigma[i]=rho[i]"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(rhosigma_[i+n], 1, sigma_[i]), "rhosigma[i+n]=sigma[i]"
		);

	}

}

template<typename FieldT>
void cp_aggregate_gadget<FieldT>::generate_r1cs_witness()
{
	for(size_t i=0; i < size_enforcers_.size(); ++i)
		size_enforcers_[i].generate_r1cs_witness();

	size_t n = x_.size() - 1;
	for(size_t i=0; i < n; ++i)
	{
		this->pb.val(XY_[i]) = this->pb.val(x_[i+1]);
		this->pb.val(XY_[i+n]) = this->pb.val(y_[i+1]);
		this->pb.val(Zext_[i]) = this->pb.val(z_[i+1]);
		this->pb.val(Zext_[i+n]) = FieldT::zero();
		this->pb.val(deltaext_[i]) = this->pb.val(delta_[i]);
		this->pb.val(deltaext_[i+n]) = FieldT::zero();
		this->pb.val(rhosigma_[i]) = this->pb.val(rho_[i]);
		this->pb.val(rhosigma_[i+n]) = this->pb.val(sigma_[i]);
	}	
}

template<typename FieldT>
class cp_equality_gadget : public gadget<FieldT> 
{
	public:
	cp_equality_gadget(
		protoboard<FieldT>& pb,
		const pb_variable<FieldT>& v,
		const pb_variable_array<FieldT>& x,
		const pb_variable_array<FieldT>& f,
		const std::string& annotation_prefix=""
	);

	void generate_r1cs_constraints();

	void generate_r1cs_witness();

	private:
	pb_variable<FieldT> v_;
	pb_variable<FieldT> s_;
	pb_variable_array<FieldT> X_;
	pb_variable_array<FieldT> f_;
	// auxiliary inputs
	pb_variable_array<FieldT> rho_;
	pb_variable_array<FieldT> F_;
	pb_variable_array<FieldT> u_, w_;

	std::vector<size_enforcing_gadget<FieldT>> size_enforcer_;
};

template<typename FieldT>
cp_equality_gadget<FieldT>::cp_equality_gadget(
	protoboard<FieldT>& pb,
	const pb_variable<FieldT>& v,
	const pb_variable_array<FieldT>& x,
	const pb_variable_array<FieldT>& f,
	const std::string& annotation_prefix):
	gadget<FieldT>(pb, annotation_prefix),
	v_(v),
	s_(x[0]),
	X_(x.begin()+1, x.end()),
	f_(f)
{
	rho_.allocate(this->pb, X_.size(), "rho");
	F_.allocate(this->pb, X_.size(), "F");
	u_.allocate(this->pb, X_.size(), "u");
	w_.allocate(this->pb, X_.size(), "w");
	size_enforcer_.emplace_back(
		size_enforcing_gadget<FieldT>(
			this->pb,
			rho_.size(),
			s_,
			rho_,
			"s <-> rho"
		)
	);

	size_enforcer_[0].allocate();
}


template<typename FieldT>
void cp_equality_gadget<FieldT>::generate_r1cs_constraints()
{
	// Summary of constraints
	// SizeEnforce(s, rho)
	// u.w = 1 non-zero twins
	// (X - v).u = 1 - F
	// rho o F = f

	size_enforcer_[0].generate_r1cs_constraints();
	size_t N = X_.size();

	for(size_t i=0; i < N; ++i)
	{
		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(u_[i], w_[i], 1), "u.v=1"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(X_[i] - v_, u_[i], 1 - F_[i]), "(X-v)u = 1 - F"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(rho_[i], F_[i], f_[i]), "rho.F = f"
		);
	}

}

template<typename FieldT>
void cp_equality_gadget<FieldT>::generate_r1cs_witness()
{
	size_enforcer_[0].generate_r1cs_witness();
	size_t N = X_.size();

	for(size_t i=0; i < N; ++i)
	{
		if (this->pb.val(X_[i] == this->pb.val(v_)))
		{
			this->pb.val(u_[i]) = 1;
			this->pb.val(w_[i]) = 1;
			this->pb.val(F_[i]) = 1;
		} else {
			this->pb.val(F_[i]) = 0;
			this->pb.val(u_[i]) = (this->pb.val(X_[i]) - this->pb.val(v_)).inverse();
			this->pb.val(w_[i]) = (this->pb.val(u_[i])).inverse();
		}
	
		this->pb.val(f_[i]) = this->pb.val(rho_[i]) * this->pb.val(F_[i]);

	}

}



template<typename FieldT>
class multi_hash_consistency_gadget : public gadget<FieldT>
{
	private:
	pb_variable<FieldT> s_;
	pb_variable_array<FieldT> x_;
	pb_variable_array<FieldT> multi_hashes_;
	pb_variable_array<FieldT> X_;
	pb_variable_array<FieldT> intermediate_keys_;

	std::vector<mimc_cipher<FieldT>> hashers_;

	public:
	multi_hash_consistency_gadget(
		protoboard<FieldT>& pb,
		const pb_variable_array<FieldT>& x,					// input
		const pb_variable_array<FieldT>& multi_hashes,		// outputs
		const std::string& annotation_prefix=""
	);

	void generate_r1cs_constraints();

	void generate_r1cs_witness();
};

template<typename FieldT>
multi_hash_consistency_gadget<FieldT>::multi_hash_consistency_gadget(
	protoboard<FieldT>& pb,
	const pb_variable_array<FieldT>& x,
	const pb_variable_array<FieldT>& multi_hashes,
	const std::string& annotation_prefix
): gadget<FieldT>(pb, annotation_prefix),
x_(x),
s_(x[0]),
multi_hashes_(multi_hashes),
X_(x.begin() + 1, x.end())
{
	size_t h = sizeof(partial_hash_sizes)/sizeof(size_t);
	size_t rounds = partial_hash_sizes[h-1];

	assert(multi_hashes_.size() == h);
	assert(X_.size() >= rounds);

	intermediate_keys_.allocate(this->pb, rounds + 1, "intermediate_keys");

	// set up the hashers
	for(size_t i=0; i < rounds; ++i)
	{
		hashers_.emplace_back(
			mimc_cipher<FieldT>(
				this->pb,
				intermediate_keys_[i],
				X_[i],
				intermediate_keys_[i+1],
				"hasher"
			)
		);
	}
}

template<typename FieldT>
void multi_hash_consistency_gadget<FieldT>::generate_r1cs_constraints()
{
	this->pb.add_r1cs_constraint(
		r1cs_constraint<FieldT>(intermediate_keys_[0], 1, 0),
		"intermediate_keys[0] = 0"
	);

	for(size_t i=0; i < hashers_.size(); ++i)
		hashers_[i].generate_r1cs_constraints();

	for(size_t i=0; i < multi_hashes_.size(); ++i)
	{
		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(multi_hashes_[i], 1, intermediate_keys_[ partial_hash_sizes[i] ]),
			"output multi_hashes"
		);
	}	
}

template<typename FieldT>
void multi_hash_consistency_gadget<FieldT>::generate_r1cs_witness()
{
	this->pb.val(intermediate_keys_[0]) = 0;
	for(size_t i=0; i < hashers_.size(); ++i)
		hashers_[i].generate_r1cs_witness();

	for(size_t i=0; i < multi_hashes_.size(); ++i)
	{
		this->pb.val(multi_hashes_[i]) = this->pb.val(intermediate_keys_[ partial_hash_sizes[i] ]);
	}
}


template<typename FieldT>
class cp_decision_tree_gadget : public gadget<FieldT>
{
	private:
	size_t h_, bit_width_, d_, n_;
	pb_variable_array<FieldT> data_;
	pb_variable_array<FieldT> predictions_;
	pb_variable_array<FieldT> V_;
	pb_variable_array<FieldT> T_;
	pb_variable_array<FieldT> L_;
	pb_variable_array<FieldT> R_;
	pb_variable_array<FieldT> C_;

	// auxiliary
	pb_variable_array<FieldT> p_;
	pb_variable_array<FieldT> f_;
	pb_variable_array<FieldT> t_;
	pb_variable_array<FieldT> l_;
	pb_variable_array<FieldT> r_;
	pb_variable_array<FieldT> c_;

	pb_variable_array<FieldT> v_;
	pb_variable_array<FieldT> less_, less_or_eq_;


	std::vector<polynomial_evaluation_gadget<FieldT>> poly_gadgets_;
	std::vector<comparison_gadget<FieldT>> comparators_;

	public:
	cp_decision_tree_gadget(
		protoboard<FieldT>& pb,
		size_t h, // height
		size_t bit_width, // bit width of data
		size_t d, // dimensions
		size_t n, // samples
		const pb_variable_array<FieldT>& data,
		const pb_variable_array<FieldT>& predictions,
		const pb_variable_array<FieldT>& V,
		const pb_variable_array<FieldT>& T,
		const pb_variable_array<FieldT>& L,
		const pb_variable_array<FieldT>& R,
		const pb_variable_array<FieldT>& C,
		const pb_variable_array<FieldT>& p,
		const pb_variable_array<FieldT>& f,
		const pb_variable_array<FieldT>& t,
		const pb_variable_array<FieldT>& l,
		const pb_variable_array<FieldT>& r,
		const pb_variable_array<FieldT>& c,
		const std::string& annotation_prefix=""
	): gadget<FieldT>(pb, annotation_prefix),
	h_(h), bit_width_(bit_width), d_(d), n_(n),
	data_(data), predictions_(predictions),
	V_(V),
	T_(T),
	L_(L),
	R_(R),
	C_(C),
	p_(p),
	f_(f),
	t_(t),
	l_(l),
	r_(r),
	c_(c)
	{
		v_.allocate(this->pb, h*n, "v_");
		less_.allocate(this->pb, h*n, "less");
		less_or_eq_.allocate(this->pb, h*n, "less_or_eq");

		for(size_t i=0; i < n; ++i)
		{
			pb_variable_array<FieldT> ipoly(data_.begin() + i*d, data_.begin() + i*d + d);
			for(size_t j=0; j < h; ++j)
			{
				poly_gadgets_.emplace_back(
					polynomial_evaluation_gadget<FieldT>(
						this->pb,
						ipoly,
						f_[i*h + j],
						v_[i*h + j]
					)
				);

				comparators_.emplace_back(
					comparison_gadget<FieldT>(
						this->pb,
						bit_width_,
						v_[i * h + j],
						t_[i * h + j],
						less_[i * h + j],
						less_or_eq_[i * h + j],
						"comparator"
					)
				);
			}
		}

	};

	void generate_r1cs_constraints()
	{
		for(size_t i=0; i < poly_gadgets_.size(); ++i)
			poly_gadgets_[i].generate_r1cs_constraints();

		for(size_t i=0; i < comparators_.size(); ++i)
			comparators_[i].generate_r1cs_constraints();

		// decision path constraint
		for(size_t i=0; i < n_; ++i)
		{
			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(
					p_[i * h_],
					1,
					0
				), "Start decision path with 0"
			);

			for(size_t j=0; j < h_ - 1; ++j)
			{
				this->pb.add_r1cs_constraint(
					r1cs_constraint<FieldT>(
						less_or_eq_[i * h_ + j],
						l_[i * h_ + j] - r_[i * h_ + j],
						p_[i * h_ + j + 1] - r_[i * h_ + j]),
					"path constraint"
				);
			}
		}

		// constrain predictions
		for(size_t i=0; i < n_; ++i)
		{
			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(
					predictions_[i],
					1,
					c_[i * h_ + (h_ - 1)]					
				),
				"predictions"
			);
		}

	};


	void generate_r1cs_witness()
	{
		for(size_t i=0; i < n_; ++i)
		{
			this->pb.val(p_[i*h_]) = 0;
			for(size_t j=0; j < h_; ++j)
			{
				size_t node_id = static_cast<size_t>(this->pb.val(p_[i*h_ + j]).as_ulong());
				size_t var_id = static_cast<size_t>(this->pb.val(V_[node_id]).as_ulong());
				size_t thr = static_cast<size_t>(this->pb.val(T_[node_id]).as_ulong());
				size_t left_id = static_cast<size_t>(this->pb.val(L_[node_id]).as_ulong());
				size_t right_id = static_cast<size_t>(this->pb.val(R_[node_id]).as_ulong());
				size_t label = static_cast<size_t>(this->pb.val(C_[node_id]).as_ulong());

				this->pb.val(f_[i*h_ + j]) = var_id;
				this->pb.val(t_[i*h_ + j]) = thr;
				this->pb.val(l_[i*h_ + j]) = left_id;
				this->pb.val(r_[i*h_ + j]) = right_id;
				this->pb.val(c_[i*h_ + j]) = label;

				poly_gadgets_[i*h_ + j].generate_r1cs_witness();
				comparators_[i*h_ + j].generate_r1cs_witness();

				size_t value = static_cast<size_t>(this->pb.val(v_[i*h_ + j]).as_ulong());

				if (j < h_ - 1)
				{
					if (value <= thr)
					{
						this->pb.val(p_[i * h_ + j + 1]) = this->pb.val(l_[i * h_ + j]);
					}
					else
						this->pb.val(p_[i * h_ + j + 1]) = this->pb.val(r_[i * h_ + j]);
				}
			}

		}

		for(size_t i=0; i < n_; ++i)
		{
			this->pb.val(predictions_[i]) = this->pb.val(c_[i * h_ + (h_ - 1)]);
		}
	};

};

} // namespace

#endif