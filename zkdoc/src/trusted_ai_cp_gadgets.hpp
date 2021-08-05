#ifndef __TRUSTED_AI_CP_GADGETS__
#define __TRUSTED_AI_CP_GADGETS__

#include <zkdoc/src/trusted_ai_interactive_gadgets.hpp>
#include <zkdoc/src/trusted_ai_utility_gadgets.hpp>

using namespace libsnark;

namespace TrustedAI {

template<typename FieldT>
class cp_filter_gadget : public gadget<FieldT> 
{
	public:
	cp_filter_gadget(
		protoboard<FieldT>& pb,
		const pb_variable_array<FieldT>& x,
		const pb_variable_array<FieldT>& f,
		const pb_variable_array<FieldT>& y,
		const pb_variable_array<FieldT>& tilde_f,
		const pb_variable_array<FieldT>& U,
		const pb_variable_array<FieldT>& delta,
		const pb_variable_array<FieldT>& V,
		const std::string& annotation_prefix=""
	);

	void generate_r1cs_constraints();

	void generate_r1cs_witness();

	private:
	pb_variable<FieldT> s_;
	pb_variable_array<FieldT> X_;
	pb_variable<FieldT> t_;
	pb_variable_array<FieldT> Y_;
	pb_variable_array<FieldT> f_;
	pb_variable_array<FieldT> U_, delta_, V_, tilde_f_;
	pb_variable_array<FieldT> rho_;

	std::vector<hadamard_product_gadget<FieldT>> prod_gadgets_;
	std::vector<size_enforcing_gadget<FieldT>> size_gadgets_;

};

template<typename FieldT>
cp_filter_gadget<FieldT>::cp_filter_gadget(
	protoboard<FieldT>& pb,
	const pb_variable_array<FieldT>& x,
	const pb_variable_array<FieldT>& f,
	const pb_variable_array<FieldT>& y,
	const pb_variable_array<FieldT>& tilde_f,
	const pb_variable_array<FieldT>& U,
	const pb_variable_array<FieldT>& delta,
	const pb_variable_array<FieldT>& V,
	const std::string& annotation_prefix):
	gadget<FieldT>(pb, annotation_prefix),
	s_(x[0]),
	X_(x.begin()+1, x.end()),
	f_(f),
	t_(y[0]),
	Y_(y.begin()+1, y.end()),
	tilde_f_(tilde_f),
	U_(U),
	delta_(delta),
	V_(V)
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

	prod_gadgets_.emplace_back(
		hadamard_product_gadget<FieldT>(
			this->pb,
			rho_,
			f_,
			tilde_f_,
			"rho o f = tilde_f"
		)
	);

	prod_gadgets_.emplace_back(
		hadamard_product_gadget<FieldT>(
			this->pb,
			tilde_f_,
			X_,
			U_,
			"tilde_f o X = U"
		)
	);

	prod_gadgets_.emplace_back(
		hadamard_product_gadget<FieldT>(
			this->pb,
			delta_,
			Y_,
			V_,
			"delta o Y = V"
		)
	);

	for(size_t i=0; i < size_gadgets_.size(); ++i)
		size_gadgets_[i].allocate();
	
}

template<typename FieldT>
void cp_filter_gadget<FieldT>::generate_r1cs_constraints()
{
	for(size_t i=0; i < size_gadgets_.size(); ++i) size_gadgets_[i].generate_r1cs_constraints();
	for(size_t i=0; i < prod_gadgets_.size(); ++i) prod_gadgets_[i].generate_r1cs_constraints();

}

template<typename FieldT>
void cp_filter_gadget<FieldT>::generate_r1cs_witness()
{
	for(size_t i=0; i < size_gadgets_.size(); ++i) size_gadgets_[i].generate_r1cs_witness();
	for(size_t i=0; i < prod_gadgets_.size(); ++i) prod_gadgets_[i].generate_r1cs_witness();
}

template<typename FieldT>
class increment_gadget : public gadget<FieldT>
{
	// 
	//	incr_i = 1 if idx \neq limit_i + 1 and y <= z
	//  incr_j = 1 if idx \neq limit_j + 1 and y >= z
	//  else incr = 0
	//  b = (idx - limit).w
	//  wz = 1
	//  b(1-b) = 0
	//  less, less_eq = comparison(y, z)
	//  incr = 

	private:
	size_t bit_width_;
	pb_variable<FieldT> y_, z_, idx_i_, idx_j_, limit_i_, limit_j_;
	pb_variable<FieldT> incr_i_, incr_j_;
	pb_variable<FieldT> less_, less_or_eq_;
	pb_variable<FieldT> b_i, b_j, w_i, w_j, z_i, z_j;
	std::vector<comparison_gadget<FieldT>> comparator_;
	public:
	increment_gadget(
		protoboard<FieldT>& pb,
		size_t bit_width,
		const pb_variable<FieldT>& y,
		const pb_variable<FieldT>& z,
		const pb_variable<FieldT>& idx_i,
		const pb_variable<FieldT>& idx_j,
		const pb_variable<FieldT>& limit_i,
		const pb_variable<FieldT>& limit_j,
		const pb_variable<FieldT>& incr_i,
		const pb_variable<FieldT>& incr_j,
		const std::string& annotation_prefix=""
	): gadget<FieldT>(pb, annotation_prefix),
	bit_width_(bit_width),
	y_(y),
	z_(z),
	idx_i_(idx_i),
	idx_j_(idx_j),
	limit_i_(limit_i),
	limit_j_(limit_j),
	incr_i_(incr_i),
	incr_j_(incr_j)
	{
		less_.allocate(this->pb, "less");
		less_or_eq_.allocate(this->pb, "less_or_eq");
		b_i.allocate(this->pb, "b_i");
		b_j.allocate(this->pb, "b_j");
		w_i.allocate(this->pb, "w_i");
		w_j.allocate(this->pb, "w_j");
		z_i.allocate(this->pb, "z_i");
		z_j.allocate(this->pb, "z_j");

		comparator_.emplace_back(
			comparison_gadget<FieldT>(
				this->pb,
				bit_width_,
				y_,
				z_,
				less_,
				less_or_eq_,
				"comparator"
			)
		);

	};

	void generate_r1cs_constraints()
	{
		generate_boolean_r1cs_constraint<FieldT>(this->pb, b_i, "b_i");
		generate_boolean_r1cs_constraint<FieldT>(this->pb, b_j, "b_j");
		
		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(w_i, z_i, 1), "w_i.z_i = 1"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(w_j, z_j, 1), "w_j.z_j = 1"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(w_i, limit_i_ - idx_i_, b_i), "w_i.(limit_i - idx_i +1)=b_i"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(w_j, limit_j_ - idx_j_, b_j), "w_j.(limit_j - idx_j +1)=b_j"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(b_i, less_or_eq_, incr_i_), "incr_i = b_i.less_or_eq"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(b_j, 1 - less_, incr_j_), "incr_j = b_j.(1-less)"
		);


		comparator_[0].generate_r1cs_constraints();

	};


	void generate_r1cs_witness()
	{
		comparator_[0].generate_r1cs_witness();

		if (this->pb.val(limit_i_) == this->pb.val(idx_i_)) {
			this->pb.val(w_i) = FieldT::one();
			this->pb.val(b_i) = 0;
		} else {
			this->pb.val(w_i) = (this->pb.val(limit_i_) - this->pb.val(idx_i_)).inverse();
			this->pb.val(b_i) = 1;
		}

		if (this->pb.val(limit_j_) == this->pb.val(idx_j_)) {
			this->pb.val(w_j) = FieldT::one();
			this->pb.val(b_j) = 0;
		} else {
			this->pb.val(w_j) = (this->pb.val(limit_j_) - this->pb.val(idx_j_)).inverse();
			this->pb.val(b_j) = 1;
		}

		this->pb.val(z_i) = this->pb.val(w_i).inverse();
		this->pb.val(z_j) = this->pb.val(w_j).inverse();

		this->pb.val(incr_i_) = this->pb.val(b_i) * this->pb.val(less_or_eq_);
		this->pb.val(incr_j_) = this->pb.val(b_j) * (FieldT::one() - this->pb.val(less_));

	};


};

template<typename FieldT>
class cp_inner_join_gadget : public gadget<FieldT> 
{
	public:
	size_t bit_width_;
	pb_variable<FieldT> s1_, s2_, t1_, t2_, k1_, k2_, k3_;
	pb_variable_array<FieldT> X_, Y_, Z_, W_, P_, Q_, R_;
	pb_variable_array<FieldT> tr_X_, tr_Y_, tr_Z_, tr_W_, tr_I_, tr_J_, tr_O_, tr_S_;
	pb_variable_array<FieldT> tilde_delta_, tilde_p_, tilde_q_, tilde_r_;
	pb_variable_array<FieldT> delta_;
	pb_variable_array<FieldT> incr_i_, incr_j_;
	pb_variable_array<FieldT> T_, K_, L_;

	// other gadgets
	std::vector<increment_gadget<FieldT>> increment_gadgets_;
	std::vector<size_enforcing_gadget<FieldT>> size_gadgets_;
	std::vector<hadamard_product_gadget<FieldT>> prod_gadgets_;


	public:
	cp_inner_join_gadget(
		protoboard<FieldT>& pb,
		size_t bit_width,
		// full columns of length N+1 
		const pb_variable_array<FieldT>& x,
		const pb_variable_array<FieldT>& y,
		const pb_variable_array<FieldT>& z,
		const pb_variable_array<FieldT>& w,
		const pb_variable_array<FieldT>& p,
		const pb_variable_array<FieldT>& q,
		const pb_variable_array<FieldT>& r,
		// transcript (auxiliary input from prover)
		const pb_variable_array<FieldT>& tr_X,
		const pb_variable_array<FieldT>& tr_Y,
		const pb_variable_array<FieldT>& tr_Z,
		const pb_variable_array<FieldT>& tr_W,
		const pb_variable_array<FieldT>& tr_I,
		const pb_variable_array<FieldT>& tr_J,
		const pb_variable_array<FieldT>& tr_O,
		const pb_variable_array<FieldT>& tr_S,
		// vectors computed in circuit
		const pb_variable_array<FieldT>& tilde_delta,
		const pb_variable_array<FieldT>& tilde_p,
		const pb_variable_array<FieldT>& tilde_q,
		const pb_variable_array<FieldT>& tilde_r,
		const std::string& annotation_prefix = ""):
		gadget<FieldT>(pb, annotation_prefix),
		bit_width_(bit_width),
		s1_(x[0]),
		X_(x.begin()+1, x.end()),
		s2_(y[0]),
		Y_(y.begin()+1, y.end()),
		t1_(z[0]),
		Z_(z.begin()+1, z.end()),
		t2_(w[0]),
		W_(w.begin()+1, w.end()),
		k1_(p[0]),
		P_(p.begin()+1, p.end()),
		k2_(q[0]),
		Q_(q.begin()+1, q.end()),
		k3_(r[0]),
		R_(r.begin()+1, r.end()),
		tr_X_(tr_X), tr_Y_(tr_Y), tr_Z_(tr_Z),
		tr_W_(tr_W), tr_I_(tr_I), tr_J_(tr_J),
		tr_O_(tr_O), tr_S_(tr_S), tilde_delta_(tilde_delta),
		tilde_p_(tilde_p), tilde_q_(tilde_q),
		tilde_r_(tilde_r)
	{
		size_t trsize = X_.size() + Y_.size();
		std::cout << trsize << std::endl;
		delta_.allocate(this->pb, P_.size(), "delta");
		T_.allocate(this->pb, trsize, "T");
		K_.allocate(this->pb, trsize, "K");
		L_.allocate(this->pb, trsize, "L");
		incr_i_.allocate(this->pb, trsize - 1, "incr_i");
		incr_j_.allocate(this->pb, trsize - 1, "incr_j");


		size_gadgets_.emplace_back(
			size_enforcing_gadget<FieldT>(
				this->pb,
				delta_.size(),
				k1_,
				delta_,
				"size delta"
			)
		);

		size_gadgets_[0].allocate();

		for(size_t i=0; i < trsize - 1; ++i)
		{
			increment_gadgets_.emplace_back(
				increment_gadget<FieldT>(
					this->pb,
					bit_width_,
					tr_Y_[i],
					tr_Z_[i],
					tr_I_[i],
					tr_J_[i],
					s1_,
					t1_,
					incr_i_[i],
					incr_j_[i],
					"increment"
				)
			);
		}
	};

	void generate_r1cs_constraints()
	{
		size_t trsize = X_.size() + Y_.size();

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(s1_, 1, s2_), "s1=s2"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(t1_, 1, t2_), "t1=t2"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(k1_, 1, k2_), "k1=k2"
		);

		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(k2_, 1, k3_), "k2=k3"
		);

		size_gadgets_[0].generate_r1cs_constraints();
		
		for(size_t i=0; i < trsize - 1; ++i)
			increment_gadgets_[i].generate_r1cs_constraints();

		// multiplication constraints
		this->pb.add_r1cs_constraint(
			r1cs_constraint<FieldT>(tr_O_[0],1,0), "tr_O_[0]=0"
		);

		for(size_t i=0; i < trsize - 1; ++i)
		{

			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(tr_I_[i] + incr_i_[i], 1, tr_I_[i+1]), "increment I"
			);

			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(tr_J_[i] + incr_j_[i], 1, tr_J_[i+1]), "increment J"
			);
		}

		for(size_t i=0; i < trsize; ++i)
		{

			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(T_[i], K_[i], 1 - tr_S_[i]), "T.K = 1-S"
			);

			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(K_[i], L_[i], 1), "K.L=1"
			);

			generate_boolean_r1cs_constraint<FieldT>(this->pb, tr_S_[i], "tr_S");

		}

		// extension constraints on tilde_delta, tilde_p, tilde_q, tilde_r
		for(size_t i=0; i < X_.size(); ++i)
		{
			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(delta_[i], 1, tilde_delta_[i]), "tilde_delta[i]=delta[i]"
			);
			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(delta_[i], P_[i], tilde_p_[i]), "tilde_p = delta o P"
			);
			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(delta_[i], Q_[i], tilde_q_[i]), "tilde_q = delta o Q"
			);
			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(delta_[i], R_[i], tilde_r_[i]), "tilde_r = delta o R"
			);
			
		}

		for(size_t i = X_.size(); i < trsize; ++i)
		{
			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(tilde_delta_[i], 1, 0), "tilde_delta[i]=0"
			);
			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(tilde_p_[i], 1, 0), "tilde_p[i]=0"
			);
			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(tilde_q_[i], 1, 0), "tilde_q[i]=0"
			);
			this->pb.add_r1cs_constraint(
				r1cs_constraint<FieldT>(tilde_r_[i], 1, 0), "tilde_r[i]=0"
			);

		}

	};


	void generate_r1cs_witness()
	{
		size_t trsize = X_.size() + Y_.size();
		// this should fill up the delta vector
		size_gadgets_[0].generate_r1cs_witness();
		// generate the tilde vectors
		for(size_t i=0; i < X_.size(); ++i)
		{
			this->pb.val(tilde_delta_[i]) = this->pb.val(delta_[i]);
			this->pb.val(tilde_p_[i]) = this->pb.val(P_[i]) * this->pb.val(delta_[i]);
			this->pb.val(tilde_q_[i]) = this->pb.val(Q_[i]) * this->pb.val(delta_[i]);
			this->pb.val(tilde_r_[i]) = this->pb.val(R_[i]) * this->pb.val(delta_[i]);

		}

		// generate increment witnesses
		for(size_t i=0; i < trsize - 1; ++i)
			increment_gadgets_[i].generate_r1cs_witness();
		
		// set T, K, L
		for(size_t i=0; i < trsize; ++i)
		{
			if (this->pb.val(tr_S_[i]) == FieldT::one())
			{
				this->pb.val(T_[i]) = 0;
				this->pb.val(K_[i]) = 1;
				this->pb.val(L_[i]) = 1;
			} else {
				this->pb.val(T_[i]) = 1;
				this->pb.val(K_[i]) = 1;
				this->pb.val(L_[i]) = 1;
			}
		}


	};


};

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